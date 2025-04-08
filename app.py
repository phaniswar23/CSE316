from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, jsonify
import os
import hashlib
import base64
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import time
import tempfile
import subprocess
import mimetypes

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Set maximum file size to 16 MB
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted_files'
SHARE_FOLDER = 'shared_links'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(SHARE_FOLDER, exist_ok=True)

# Multiple user credentials
USERS = {
    'user1': 'password123',
    'user2': 'password456',
    'user3': 'password789'
}

# Generate encryption key
fernet_key = base64.urlsafe_b64encode(hashlib.sha256(b'securekey').digest())
fernet = Fernet(fernet_key)

# ------------------ Helper Functions ------------------ #
def encrypt_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted_data = fernet.encrypt(data)
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, os.path.basename(file_path))
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)
    return encrypted_path

def decrypt_file(file_path):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    return fernet.decrypt(encrypted_data)

def scan_with_clamav(file_path):
    try:
        result = subprocess.run(['clamscan', file_path], capture_output=True, text=True)
        return "OK" in result.stdout
    except Exception:
        return True  # Allow if clamscan fails

# ------------------ Routes ------------------ #
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if USERS.get(username) == password:
            session['pre_2fa_user'] = username
            return redirect(url_for('two_factor'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp = request.form['otp']
        if otp == '123456':
            session['user'] = session.pop('pre_2fa_user')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP', 'error')
    return render_template('2fa.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    files = os.listdir(ENCRYPTED_FOLDER)
    return render_template('dashboard.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return redirect(url_for('login'))

    file = request.files.get('file')
    if file:
        filename = secure_filename(file.filename)
        temp_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(temp_path)

        if not scan_with_clamav(temp_path):
            os.remove(temp_path)
            flash('File contains a virus and was rejected.')
            return redirect(url_for('dashboard'))

        encrypt_file(temp_path)
        os.remove(temp_path)
        flash('File uploaded and encrypted successfully.')
    return redirect(url_for('dashboard'))

@app.route('/view/<filename>')
def view_file(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        decrypted_data = decrypt_file(os.path.join(ENCRYPTED_FOLDER, filename))
    except Exception:
        flash("Error decrypting file")
        return redirect(url_for('dashboard'))

    temp = tempfile.NamedTemporaryFile(delete=False)
    temp.write(decrypted_data)
    temp.close()

    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type and mime_type.startswith('text'):
        with open(temp.name, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        os.unlink(temp.name)
        return render_template('view_text.html', filename=filename, content=content)
    elif mime_type and (mime_type.startswith('image') or mime_type == 'application/pdf'):
        return send_file(temp.name, mimetype=mime_type)
    else:
        os.unlink(temp.name)
        flash("Unsupported file format for inline view.")
        return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download_file(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    file_path = os.path.join(ENCRYPTED_FOLDER, filename)
    try:
        decrypted_data = decrypt_file(file_path)
        temp = tempfile.NamedTemporaryFile(delete=False)
        temp.write(decrypted_data)
        temp.close()
        return send_file(temp.name, as_attachment=True, download_name=filename)
    except Exception:
        flash('Error downloading file.')
        return redirect(url_for('dashboard'))

@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    file_path = os.path.join(ENCRYPTED_FOLDER, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash('File deleted.')
    return redirect(url_for('dashboard'))

@app.route('/metadata/<filename>')
def metadata(filename):
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 403
    file_path = os.path.join(ENCRYPTED_FOLDER, filename)
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    stats = os.stat(file_path)
    return jsonify({
        'Filename': filename,
        'Size (bytes)': stats.st_size,
        'Created': time.ctime(stats.st_ctime),
        'Modified': time.ctime(stats.st_mtime)
    })

@app.route('/share/<filename>')
def share_file(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    shared_path = os.path.join(SHARE_FOLDER, filename)
    orig_path = os.path.join(ENCRYPTED_FOLDER, filename)
    if os.path.exists(orig_path):
        with open(orig_path, 'rb') as f_in, open(shared_path, 'wb') as f_out:
            f_out.write(f_in.read())
        share_url = url_for('shared_file', filename=filename, _external=True)
        return jsonify({'link': share_url})
    return jsonify({'error': 'File not found'}), 404

@app.route('/shared/<filename>')
def shared_file(filename):
    shared_path = os.path.join(SHARE_FOLDER, filename)
    if os.path.exists(shared_path):
        try:
            decrypted_data = decrypt_file(shared_path)
            return decrypted_data.decode('utf-8', errors='ignore')
        except Exception:
            return 'Error reading shared file'
    return 'Shared file not found', 404

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ------------------ Error Handlers ------------------ #
@app.errorhandler(413)
def file_too_large(e):
    flash('File is too large. Maximum allowed size is 16MB.')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, render_template, request, redirect, url_for, send_file, session, jsonify, flash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import base64
from cryptography.fernet import Fernet
from datetime import datetime
import pyclamd  # For malware scanning

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Simulated user database
users = {"user1": {"password": "password123"}}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    return User(username) if username in users else None

# Encryption Key
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}  # Prevent executable uploads
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB max file size

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ClamAV Setup (Ensure ClamAV is running)
try:
    scanner = pyclamd.ClamdAgnostic()
    if not scanner.ping():
        print("ClamAV not running. Please start ClamAV.")
except Exception as e:
    print("Error connecting to ClamAV:", e)

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def is_malicious(file_path):
    """Scan file for malware using ClamAV"""
    try:
        scan_result = scanner.scan_file(file_path)
        return scan_result and "FOUND" in str(scan_result)
    except Exception as e:
        print("Malware scanning error:", e)
        return False

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username in users and users[username]["password"] == password:
            login_user(User(username))
            session["username"] = username
            return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("username", None)
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], session["username"])
    os.makedirs(user_folder, exist_ok=True)
    files = os.listdir(user_folder)
    return render_template("dashboard.html", files=files)

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        flash("No file selected!", "error")
        return redirect(request.url)

    file = request.files["file"]
    if file.filename == "" or not allowed_file(file.filename):
        flash("Invalid file type!", "error")
        return redirect(request.url)

    if len(file.read()) > MAX_FILE_SIZE:
        flash("File size exceeds limit!", "error")
        return redirect(request.url)
    
    file.seek(0)  # Reset file pointer after reading size

    filename = secure_filename(file.filename)
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], session["username"])
    os.makedirs(user_folder, exist_ok=True)

    file_path = os.path.join(user_folder, filename)

    # Save file temporarily to scan for malware
    file.save(file_path)

    if is_malicious(file_path):
        os.remove(file_path)
        flash("Malware detected! Upload blocked.", "error")
        return redirect(url_for("dashboard"))

    # Encrypt file
    with open(file_path, "rb") as f:
        encrypted_data = cipher.encrypt(f.read())

    with open(file_path, "wb") as f:
        f.write(encrypted_data)

    flash("File uploaded successfully!", "success")
    return redirect(url_for("dashboard"))

@app.route("/view/<filename>")
@login_required
def view_file(filename):
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], session["username"])
    file_path = os.path.join(user_folder, filename)

    if not os.path.exists(file_path):
        return "File not found!", 404

    with open(file_path, "rb") as file:
        decrypted_data = cipher.decrypt(file.read())

    return decrypted_data.decode("utf-8", errors="ignore")

@app.route("/download/<filename>")
@login_required
def download_file(filename):
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], session["username"])
    file_path = os.path.join(user_folder, filename)

    if not os.path.exists(file_path):
        return "File not found!", 404

    with open(file_path, "rb") as file:
        decrypted_data = cipher.decrypt(file.read())

    decrypted_file_path = file_path + "_decrypted"
    with open(decrypted_file_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

    return send_file(decrypted_file_path, as_attachment=True)

@app.route("/delete/<filename>", methods=["POST"])
@login_required
def delete_file(filename):
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], session["username"])
    file_path = os.path.join(user_folder, filename)

    if os.path.exists(file_path):
        os.remove(file_path)

    flash("File deleted!", "success")
    return redirect(url_for("dashboard"))

@app.route("/metadata/<filename>")
@login_required
def file_metadata(filename):
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], session["username"])
    file_path = os.path.join(user_folder, filename)

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found!"}), 404

    metadata = {
        "Filename": filename,
        "Size (bytes)": os.path.getsize(file_path),
        "Created": datetime.fromtimestamp(os.path.getctime(file_path)).strftime("%Y-%m-%d %H:%M:%S"),
        "Modified": datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M:%S"),
    }

    return jsonify(metadata)

if __name__ == "__main__":
    app.run(debug=True)

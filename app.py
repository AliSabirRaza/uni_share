import os
import shutil
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Cryptographically signs user session cookies safely using a persistent key
app.secret_key = 'uni_share_permanent_production_secret_string_key'

# 🛠️ CLOUD PRODUCTION DATABASE PATH CORRECTION
# Moving database.db to /tmp bypasses read-only storage restrictions on cloud containers
if os.name == 'nt':  # If running locally on Windows
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "database.db")}'
    app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
else:  # If running publicly on Linux Cloud (Railway)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/database.db'
    app.config['UPLOAD_FOLDER'] = '/tmp/uploads'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 🛡️ SYSTEM ACCESS PRIVILEGES DATABASE (STRICT CLOUD REFERENCE LIST)
AUTHORIZED_GMAILS = [
    'ali.sabir@student.giqi.edu.pk',
    'admin@gmail.com',
    'professor@gmail.com'
]

# 🗄️ SECURE DATABASE MODELS (SQL)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    username = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

DEFAULT_SUBJECTS = ['Mathematics', 'Physics', 'Computer Science']

def init_system():
    # 1. ALWAYS CREATE THE PHYSICAL UPLOADS DIRECTORY FIRST
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
    for subject in DEFAULT_SUBJECTS:
        subj_path = os.path.join(app.config['UPLOAD_FOLDER'], subject)
        if not os.path.exists(subj_path):
            os.makedirs(subj_path, exist_ok=True)

    # 2. THEN BUILD THE DATABASE TABLES
    with app.app_context():
        db.create_all()

# --- INITIALIZE SYSTEM AT GLOBAL SCOPE FOR GUNICORN PRODUCTION WORKERS ---
init_system()

@app.route('/')
def index():
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        file_structure = {}
    else:
        subjects = [d for d in os.listdir(app.config['UPLOAD_FOLDER']) if os.path.isdir(os.path.join(app.config['UPLOAD_FOLDER'], d))]
        file_structure = {subj: os.listdir(os.path.join(app.config['UPLOAD_FOLDER'], subj)) for subj in subjects}
    
    user_email = session.get('email')
    username = session.get('username')
    is_admin = user_email in AUTHORIZED_GMAILS
    
    return render_template('index.html', structure=file_structure, email=user_email, username=username, is_admin=is_admin)

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form.get('email').strip().lower()
    username = request.form.get('username').strip()
    password = request.form.get('password')
    
    existing_user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
    if existing_user:
        flash("An account with this email already exists.", "danger")
        return redirect(url_for('index'))
        
    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
    
    new_user = User(email=email, username=username, password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    
    session['email'] = email
    session['username'] = username
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email').strip().lower()
    password = request.form.get('password')
    
    if session.get('locked_out'):
        flash("Account login disabled due to excessive failures. Restart session to reset.", "danger")
        return redirect(url_for('index'))

    user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
    
    if user and check_password_hash(user.password_hash, password):
        session.pop('login_attempts', None)
        session.pop('locked_out', None)
        session['email'] = email
        session['username'] = user['username']
        return redirect(url_for('index'))
        
    attempts = session.get('login_attempts', 0) + 1
    session['login_attempts'] = attempts
    max_allowed_retries = 3
    remaining_retries = max_allowed_retries - attempts
    
    if remaining_retries <= 0:
        session['locked_out'] = True
        flash("Too many failed attempts. You have been locked out.", "danger")
    else:
        flash(f"Invalid email or password. You have {remaining_retries} retries remaining.", "danger")
        
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if not session.get('email'):
        flash("Session expired or unauthorized.", "danger")
        return redirect(url_for('index'))
        
    username = session.get('username')
    subject = request.form.get('subject')
    file = request.files.get('file')
    
    if file and subject and '..' not in subject:
        target_dir = os.path.join(app.config['UPLOAD_FOLDER'], subject)
        if os.path.exists(target_dir):
            clean_filename = os.path.basename(file.filename)
            name, ext = os.path.splitext(clean_filename)
            custom_filename = f"{name} (by @{username}){ext}"
            file.save(os.path.join(target_dir, custom_filename))
            
    return redirect(url_for('index'))

@app.route('/create-folder', methods=['POST'])
def create_folder():
    if session.get('email') not in AUTHORIZED_GMAILS:
        flash("Security Alert: Unauthorized directory manipulation attempt recorded.", "danger")
        return redirect(url_for('index'))
        
    folder_name = request.form.get('folder_name').strip()
    if folder_name and '..' not in folder_name:
        new_dir = os.path.join(app.config['UPLOAD_FOLDER'], folder_name)
        if not os.path.exists(new_dir):
            os.makedirs(new_dir, exist_ok=True)
    return redirect(url_for('index'))

@app.route('/delete-file', methods=['POST'])
def delete_file():
    if session.get('email') not in AUTHORIZED_GMAILS:
        flash("Security Alert: Unauthorized erasure sequence requested.", "danger")
        return redirect(url_for('index'))
        
    subject = request.form.get('subject')
    filename = request.form.get('filename')
    
    if subject and filename and '..' not in subject and '..' not in filename:
        file_to_delete = os.path.join(app.config['UPLOAD_FOLDER'], subject, filename)
        if os.path.exists(file_to_delete):
            os.remove(file_to_delete)
    return redirect(url_for('index'))

@app.route('/delete-folder', methods=['POST'])
def delete_folder():
    if session.get('email') not in AUTHORIZED_GMAILS:
        flash("Security Alert: Unauthorized destructive operation recorded.", "danger")
        return redirect(url_for('index'))
        
    subject = request.form.get('subject')
    if subject and '..' not in subject:
        folder_to_delete = os.path.join(app.config['UPLOAD_FOLDER'], subject)
        if os.path.exists(folder_to_delete):
            shutil.rmtree(folder_to_delete)
    return redirect(url_for('index'))

@app.route('/download/<subject>/<filename>')
def download_file(subject, filename):
    if not session.get('email'):
        return "Unauthorized Access", 403
    if '..' in subject or '..' in filename:
        return "Bad Request", 400
    target_dir = os.path.join(app.config['UPLOAD_FOLDER'], subject)
    return send_from_directory(target_dir, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)

import os
import base64
import hashlib
import random
import sqlite3
from flask import Flask, render_template, session, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from email_sender import send_email

# Flask app setup
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///img.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('FLASK_SECRET_KEY', '@FABRIC')

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Allowed file types
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Admin flag

# Image model
class Img(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(300), nullable=False)
    img = db.Column(db.LargeBinary, nullable=False)
    mimetype = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    tags = db.Column(db.String(300), nullable=False)

# Create tables if they don't exist
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Template filter for Base64 encoding
@app.template_filter('b64encode')
def b64encode_filter(data):
    if data is None:
        return ""
    return base64.b64encode(data).decode('utf-8')

def is_allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/admin', methods=["POST", "GET"])
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('welcome'))

    if request.method == "POST":
        if 'pic' not in request.files:
            return render_template('admin.html', error='No file part in the request')

        pic = request.files['pic']
        if pic.filename == '':
            return render_template('admin.html', error='No picture uploaded')

        tags = request.form.get('tags', '').strip()
        category = request.form.get('category', '').strip()
        subject = request.form.get('subject', '').strip()

        if not tags or not category or not subject:
            return render_template('admin.html', error='Tags, category, and subject are required')

        filename = secure_filename(pic.filename)
        if not is_allowed_file(filename):
            return render_template('admin.html', error='Invalid file type. Please upload an image file')

        existing_image = Img.query.filter_by(name=filename, category=category, subject=subject, tags=tags).first()
        if existing_image:
            return render_template('admin.html', error='An image with the same name and details already exists')

        try:
            img = Img(img=pic.read(), mimetype=pic.mimetype, category=category, subject=subject, name=filename, tags=tags)
            db.session.add(img)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return render_template('admin.html', error=f'Error saving image to database: {e}')

        images = Img.query.all()
        return render_template('admin.html', images=images)

    images = Img.query.all()
    return render_template('admin.html', images=images)

@app.route('/sign_up', methods=["POST", "GET"])
def sign_up():
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirmpassword = request.form['confirmpassword']
        if password != confirmpassword:
            return render_template('sign_up.html', error="Passwords do not match")

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return render_template('sign_up.html', error="Email already registered")

        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('sign_up.html')

@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        user = User.query.filter_by(email=email, password=hashed_password).first()
        if user:
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin'))
            return redirect(url_for('home'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("welcome"))

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/home')
@login_required
def home():
    images = Img.query.all()
    return render_template('home.html', images=images)

@app.route('/verify', methods=["POST", "GET"])
@login_required
def verify():
    email = current_user.email
    if request.method == "POST":
        entered_code = request.form['verification_code']
        stored_code = session.get("code")

        if stored_code and int(entered_code) == int(stored_code):
            session.pop("code", None)
            return redirect(url_for("termsagreements"))
        else:
            return render_template("emailverification.html", error="Invalid verification code. Please try again")
        
    if "code" not in session:
        verifycode = random.randint(100000, 999999)
        session["code"] = verifycode
        send_email(email, verifycode)
    return render_template("emailverification.html")

@app.route('/agreements', methods=["POST", "GET"])
@login_required
def termsagreements():
    if request.method == "POST":
        return redirect(url_for('onboarding'))
    return render_template("terms.html")

@app.route('/onboarding', methods=["POST", "GET"])
@login_required
def onboarding():
    return render_template("onboarding.html")

if __name__ == "__main__":
    app.run(debug=True, port=5001)

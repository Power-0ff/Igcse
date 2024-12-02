import os
from flask import Flask, render_template, session, url_for, redirect, request
import sqlite3
import hashlib
import random
from email_sender import send_email
from db import db_init, db
from models import Img
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///img.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('FLASK_SECRET_KEY', '@FABRIC')

db_init(app)

# Allowed extensions for file uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def is_allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/admin', methods=["POST", "GET"])
def admin():
    email = session.get('email')
    if not email:
        return redirect(url_for('login'))

    with sqlite3.connect('users.db') as con:
        cur = con.cursor()
        user = cur.execute('SELECT * FROM Authenticated_users WHERE email = ?', (email,)).fetchone()
        if not user or not user[-1]:  # Assuming `is_admin` is the last column
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
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirmpassword = request.form.get('confirmpassword', '').strip()
        ip = request.remote_addr

        if not name or not email or not password or not confirmpassword:
            return render_template('sign_up.html', error="All fields are required")
        
        if password != confirmpassword:
            return render_template('sign_up.html', error="Passwords do not match")

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        try:
            with sqlite3.connect('users.db') as con:
                cur = con.cursor()
                cur.execute('INSERT INTO Authenticated_users (name, email, password, ip, is_admin) VALUES (?, ?, ?, ?, ?)',
                            (name, email, hashed_password, ip, 0))  # Default is_admin = 0
                con.commit()
        except sqlite3.Error as e:
            return render_template('sign_up.html', error=f"Database error: {e}")

        return redirect(url_for('termsagreements'))
    return render_template('sign_up.html')


@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            return render_template('login.html', error="Both email and password are required")

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        try:
            with sqlite3.connect('users.db') as con:
                cur = con.cursor()
                user = cur.execute('SELECT * FROM Authenticated_users WHERE email = ? AND password = ?', 
                                   (email, hashed_password)).fetchone()
                if user:
                    session['email'] = email
                    session['is_admin'] = user[-1]  # Assuming `is_admin` is the last column
                    if user[-1]:  # Redirect admin users to the admin page
                        return redirect(url_for('admin'))
                    return redirect(url_for('home'))
        except sqlite3.Error as e:
            return render_template('login.html', error=f"Database error: {e}")

    return render_template('login.html')


@app.route('/')
def welcome():
    return render_template('welcome.html')


@app.route('/home')
def home():
    if "email" not in session:
        return redirect(url_for("login"))
    images = Img.query.all()
    return render_template('home.html', images=images)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("welcome"))


@app.route('/verify', methods=["POST", "GET"])
def verify():
    email = session.get("email")
    if not email:
        return redirect(url_for('login'))

    if request.method == "POST":
        entered_code = request.form.get('verification_code', '').strip()
        stored_code = session.get("code")

        if stored_code and entered_code.isdigit() and int(entered_code) == int(stored_code):
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
def termsagreements():
    if "email" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        return redirect(url_for('onboarding'))

    return render_template("terms.html")


@app.route('/onboarding', methods=["POST", "GET"])
def onboarding():
    if "email" not in session:
        return redirect(url_for("login"))

    return render_template("onboarding.html")


if __name__ == "__main__":
    app.run(debug=True, port=5001)

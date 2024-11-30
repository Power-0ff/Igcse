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


@app.route('/admin', methods=["POST", "GET"])
def admin():
    if 'admin' not in session:
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
        ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
        if not ('.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS):
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
            return render_template('admin.html', error='Error saving image to database')

        images = Img.query.all()
        return render_template('admin.html', images=images)
    images = Img.query.all()
    return render_template('admin.html', images=images)


@app.route('/sign_up', methods=["POST", "GET"])
def sign_up():
    if request.method == "POST" and 'email' in request.form and 'name' in request.form and 'password' in request.form and 'confirmpassword' in request.form:
        name = request.form['name']
        password = request.form['password']
        confirmpassword = request.form['confirmpassword']
        email = request.form['email']
        ip = request.remote_addr
        session["ip"] = ip
        
        if password != confirmpassword:
            return render_template('sign_up.html', error="Passwords do not match")

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        with sqlite3.connect('users.db') as con:
            cur = con.cursor()
            cur.execute('''INSERT INTO Authenticated_users (name, email, password, ip) 
                           VALUES (?, ?, ?, ?)''', (name, email, hashed_password, ip))
            con.commit()
        return redirect(url_for('termsagreements'))
    return render_template('sign_up.html')


@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST" and 'email' in request.form and 'password' in request.form:
        password = request.form['password']
        email = request.form['email']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if email == "admin@example.com" and hashed_password == "hashed_admin_password":
            session["admin"] = '@ADMIN'
            return redirect(url_for('admin'))

        with sqlite3.connect('users.db') as con:
            cur = con.cursor()
            user = cur.execute('SELECT * FROM Authenticated_users WHERE email = ? AND password = ?', (email, hashed_password)).fetchone()
            if user:
                session['email'] = email
                return redirect(url_for('home'))
    return render_template('login.html')


@app.route('/welcome')
def welcome():
    return render_template('welcome.html')


@app.route('/home')
def home():
    if "ip" not in session:
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
def termsagreements():
    if "ip" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        return redirect(url_for('onboarding'))
    return render_template("terms.html")


if __name__ == "__main__":
    app.run(debug=True, port=5001)

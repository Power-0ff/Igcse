from flask import Flask, render_template, session, url_for, redirect, request, flash
import auth
import sqlite3
import hashlib
import base64
import random
from email_sender import send_email
from db import db_init, db
from models import Img
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///img.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db_init(app)

app.secret_key = '@FABRIC'

from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from sqlalchemy.exc import SQLAlchemyError

@app.template_filter('b64encode')
def b64encode(data):
    return base64.b64encode(data).decode('utf-8')

@app.route('/admin', methods=["POST", "GET"])
def admin():
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
        
        if not pic.mimetype.startswith('image'):
            return render_template('admin.html', error='Invalid file type. Please upload an image file')
        
        existing_image = Img.query.filter_by(name=filename, category=category, subject=subject, tags=tags).first()
        if existing_image:
            return render_template('admin.html', error='An image with the same name and details already exists')
        
        try:
            img = Img(img=pic.read(), mimetype=pic.mimetype, category=category, subject=subject, name=filename, tags=tags)
            db.session.add(img)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            return render_template('admin.html', error='img exists')
        
        images = Img.query.all()
        return render_template('admin.html', images=images)
    images = Img.query.all()
    return render_template('admin.html', images=images)

@app.route('/sign_up', methods=["POST", "GET"])
def sign_up():
    con = sqlite3.connect('users.db')
    cur = con.cursor()
    if request.method == "POST" and 'email' in request.form and 'name' in request.form and 'password' in request.form and 'confirmpassword' in request.form:
        name = request.form['name']
        password = request.form['password']
        confirmpassword = request.form['confirmpassword']
        email = request.form['email']
        ip = request.remote_addr
        session["ip"] = ip
        token = auth.authorize_sign_up(password, confirmpassword, email)
        if token:
            session['name'] = name
            session['email'] = email
            return redirect(url_for('verify'))
    return render_template('sign_up.html')

@app.route('/login', methods = ["POST", "GET"])
def login():
    ip = request.remote_addr
    session["ip"] = ip
    if request.method == "POST" and 'email' in request.form and 'password' in request.form:
        password = request.form['password']
        password = hashlib.sha256(password.encode()).hexdigest()
        email = request.form['email']
        Token = auth.authenticate_login(password, email)
        if Token:
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
    return redirect(url_for("sign_up"))

@app.route('/')
def redir():
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
            error_message = "Invalid verification code. Please try again."
            return render_template("emailverification.html", error=error_message)
        
    if "code" not in session:
        verifycode = random.randint(10000, 999999)
        session["code"] = verifycode

        send_email(email, verifycode)
        print("email sent")

    return render_template("emailverification.html")

@app.route('/reviews')
def reviews():
    if "ip" not in session:
        return redirect(url_for("login"))
    return render_template("reviews.html")

@app.route('/onboarding', methods = ["POST", "GET"])
def onboarding():
    if "ip" not in session:
        return redirect(url_for("login"))
    if request.method == 'POST':
        name = request.form.get('name')
        age = request.form.get('age')
        class_selected = request.form.get('class')
        year = request.form.get('year')
        subjects = request.form.getlist('subjects')
        preferred_study_method = request.form.get('study_method')
        study_hours = request.form.get('study_hours')
        return redirect(url_for('home'))
    return render_template('onboarding.html')

@app.route('/agreements', methods = ["POST", "GET"])
def termsagreements():
    if "ip" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        return redirect(url_for('onboarding'))
    return render_template("terms.html")

@app.route('/settings')
def settings():
    if "ip" not in session:
        return redirect(url_for("login"))
    return render_template("settings.html")

if __name__ == "__main__":
    app.run(debug=True, port=5001)
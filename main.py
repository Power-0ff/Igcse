import os
from flask import Flask, render_template, session, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import hashlib
import random
from email_sender import send_email

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('FLASK_SECRET_KEY', '@FABRIC')

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    has_agreed_terms = db.Column(db.Boolean, default=False)
    has_completed_onboarding = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)


class Img(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(300), nullable=False)
    img = db.Column(db.LargeBinary, nullable=False)
    mimetype = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    tags = db.Column(db.String(300), nullable=True)


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
        verifycode = random.randint(100000, 999999)
        session['email'] = email
        session['code'] = verifycode
        send_email(email, verifycode)
        return redirect(url_for('verify'))
    return render_template('sign_up.html')


@app.route('/verify', methods=["POST", "GET"])
def verify():
    email = session.get("email")
    if not email:
        return redirect(url_for("sign_up"))
    user = User.query.filter_by(email=email).first()
    if not user or user.is_verified:
        return redirect(url_for("home"))
    if request.method == "POST":
        entered_code = request.form['verification_code']
        stored_code = session.get("code")
        if stored_code and int(entered_code) == int(stored_code):
            user.is_verified = True
            db.session.commit()
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
    email = session.get("email")
    if not email:
        return redirect(url_for("sign_up"))
    user = User.query.filter_by(email=email).first()
    if not user or not user.is_verified:
        return redirect(url_for("verify"))
    if user.has_agreed_terms:
        return redirect(url_for("home"))
    if request.method == "POST":
        user.has_agreed_terms = True
        db.session.commit()
        return redirect(url_for('onboarding'))
    return render_template("terms.html")


@app.route('/onboarding', methods=["POST", "GET"])
def onboarding():
    email = session.get("email")
    if not email:
        return redirect(url_for("sign_up"))
    user = User.query.filter_by(email=email).first()
    if not user or not user.has_agreed_terms:
        return redirect(url_for("agreements"))
    if user.has_completed_onboarding:
        return redirect(url_for("home"))
    if request.method == "POST":
        user.has_completed_onboarding = True
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("onboarding.html")


@app.route('/')
def welcome():
    return render_template('welcome.html')


@app.route('/home')
def home():
    if 'email' not in session:
        return redirect(url_for("login"))
    images = Img.query.all()
    return render_template('home.html', images=images)


@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST" and 'email' in request.form and 'password' in request.form:
        password = request.form['password']
        email = request.form['email']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        user = User.query.filter_by(email=email, password=hashed_password).first()
        if user:
            session['email'] = email
            session['is_admin'] = user.is_admin
            if user.is_admin:
                return redirect(url_for('admin'))
            return redirect(url_for('home'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("welcome"))


@app.route('/admin', methods=["POST", "GET"])
def admin():
    email = session.get('email')
    if not email:
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if not user or not user.is_admin:
        return redirect(url_for('home'))
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


if __name__ == "__main__":
    with app.app_context():  # Ensure that the application context is active
        db.create_all()  # Create the database tables
    app.run(debug=True, port=5001)
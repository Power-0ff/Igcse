from flask import Flask, render_template, session, url_for, redirect, request, flash
import auth
import sqlite3
import bcrypt
import random
from email_sender import send_email

app = Flask(__name__)
app.secret_key = '@FABRIC'

@app.route('/sign_up', methods=["POST", "GET"])
def sign_up():
    if request.method == "POST" and 'email' in request.form and 'name' in request.form and 'password' in request.form:
        name = request.form['name']
        password = request.form['password']
        email = request.form['email']
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        token = auth.authorize_sign_up(hashed_password, email)
        if token:
            return redirect(url_for('verify'))
    return render_template('sign_up.html')

@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST" and 'email' in request.form and 'password' in request.form:
        password = request.form['password']
        email = request.form['email']
        user = auth.get_user_by_email(email)
        if user and bcrypt.checkpw(password.encode(), user['hashed_password']):
            session['email'] = email
            return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/welcome')
def welcome():
    return render_template('welcome.html')

@app.route('/home')
def home():
    if "email" not in session:
        return redirect(url_for("login"))
    return render_template('home.html')

@app.route('/logout')
def logout():
    session.clear()
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
        if stored_code and entered_code == stored_code:
            session.pop("code", None)
            return redirect(url_for("termsagreements"))
        else:
            error_message = "Invalid verification code."
            return render_template("emailverification.html", error=error_message)
    
    if "code" not in session:
        verifycode = str(random.randint(10000, 999999))
        session["code"] = verifycode
        send_email(email, verifycode)
    return render_template("emailverification.html")

@app.route('/reviews')
def reviews():
    if "email" not in session:
        return redirect(url_for("login"))
    return render_template("reviews.html")

@app.route('/onboarding', methods=["POST", "GET"])
def onboarding():
    if "email" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        name = request.form.get('name')
        age = request.form.get('age')
        class_selected = request.form.get('class')
        year = request.form.get('year')
        subjects = request.form.getlist('subjects')
        preferred_study_method = request.form.get('study_method')
        study_hours = request.form.get('study_hours')
        
        con = sqlite3.connect('users.db')
        cur = con.cursor()
        email = session["email"]
        hashed_password = bcrypt.hashpw(session["password"].encode(), bcrypt.gensalt())
        cur.execute('''
        INSERT INTO Authenticated_users (name, email, password)
        VALUES (?, ?, ?)''', (name, email, hashed_password))
        con.commit()
        con.close()
        return redirect(url_for('home'))
    return render_template('onboarding.html')

@app.route('/agreements', methods=["POST", "GET"])
def termsagreements():
    if "email" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        return redirect(url_for('onboarding'))
    return render_template("terms.html")

@app.route('/settings')
def settings():
    if "email" not in session:
        return redirect(url_for("login"))
    return render_template("settings.html")

if __name__ == "__main__":
    app.run(debug=False, port=5001)

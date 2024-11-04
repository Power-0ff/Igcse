from flask import Flask, render_template, session, url_for, redirect, request, flash
import auth
import sqlite3
import hashlib
import random
from email_sender import send_email

app = Flask(__name__)
app.secret_key = '@FABRIC'

@app.route('/sign_up', methods=["POST", "GET"])
def sign_up():
    if request.method == "POST" and 'email' in request.form and 'name' in request.form and 'password' in request.form and 'confirmpassword' in request.form:
        name = request.form['name']
        password = request.form['password']
        confirmpassword = request.form['confirmpassword']
        email = request.form['email']
        ip = request.remote_addr
        session["ip"] = ip
        session["name"] = name
        session["email"] = email
        session["password"] = password
        token = auth.authorize_sign_up(password, confirmpassword, email)
        if token:
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
    return render_template('home.html')

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
        con = sqlite3.connect('users.db')
        cur = con.cursor()
        email = session["email"]
        ip = session["ip"]
        password = session["password"]
        name = session["name"]
        password = hashlib.sha256(password.encode()).hexdigest()
        cur.execute('''
        INSERT INTO Authenticated_users (name, email, password, ip)
        VALUES (?, ?, ?, ?)''', (name, email, password, ip))
        con.commit()
        con.close()
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
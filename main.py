from flask import Flask, render_template, session, url_for, redirect, request, flash
import auth
import sqlite3
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random

app = Flask(__name__)
app.secret_key = '@FABRIC'

def sendemail(receiver_email, message):
    sender_email = "cpal.teams@gmail.com"
    password = "wstl epmt cehp sqfd"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "Function Call Notification"
    msg.attach(MIMEText(message, 'html'))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
        print("Email sent successfully.")
    except Exception as e:
        print("Failed to send email:", e)

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
        token = auth.authorize_sign_up(password, confirmpassword, email)
        if token:
            password = hashlib.sha256(password.encode()).hexdigest()
            cur.execute('''
            INSERT INTO Authenticated_users (name, email, password, ip)
            VALUES (?, ?, ?, ?)''', (name, email, password, ip))
            con.commit()
            con.close()
            session['name'] = name
            session['email'] = email
            return redirect(url_for('termsagreements'))
    return render_template('sign_up.html')

@app.route('/login', methods = ["POST", "GET"])
def login():
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
    return render_template('home.html')

@app.route('/logout')
def logout():
    return redirect(url_for("sign_up"))

@app.route('/')
def redir():
    return redirect(url_for("welcome"))

@app.route('/verify')
def verify():
    email = session["email"]
    verifycode = random.randint(10000, 9999999)
    code = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            max-width: 600px;
            margin: auto;
        }}
        h1 {{
            color: #007BFF;
            text-align: center;
        }}
        p {{
            line-height: 1.6;
            color: #333;
        }}
        .code {{
            font-size: 24px;
            font-weight: bold;
            color: #007BFF;
            text-align: center;
            padding: 10px;
            border: 2px solid #007BFF;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            font-size: 12px;
            color: #777;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>CPAL Verification</h1>
        <p>Dear User,</p>
        <p>Thank you for choosing CPAL. To complete your registration, please use the verification code below:</p>
        <div class="code">{verifycode}</div>
        <p>If you did not request this code, please ignore this email.</p>
        <p>Best regards,<br>CPAL Team</p>
    </div>
    <div class="footer">
        &copy; {2024} CPAL. All rights reserved.
    </div>
</body>
</html>
"""
    sendemail(email, code)
    return render_template("emailverification.html")

@app.route('/reviews')
def reviews():
    return render_template("reviews.html")

@app.route('/onboarding')
def onboardroute():
    return render_template("onboarding.html")

@app.route('/agreements', methods = ["POST", "GET"])
def termsagreements():
    if request.method == "POST":
        return redirect(url_for('home'))
    return render_template("terms.html")

@app.route('/settings')
def settings():
    return render_template("settings.html")

if __name__ == "__main__":
    app.run(debug=True, port=5001)
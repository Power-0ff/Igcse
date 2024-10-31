from flask import Flask, render_template, session, url_for, redirect, request, flash
import auth
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = '@FABRIC'

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
            return redirect(url_for('home'))
    return render_template('sign_up.html')

@app.route('/login', methods = ["POST", "GET"])
def login():
    if request.method == "POST" and 'email' in request.form and 'password' in request.form:
        password = request.form['password']
        password = hashlib.sha256(password.encode()).hexdigest()
        email = request.form['email']
        Token = auth.authenticate_login(password, email)
        if Token:
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

if __name__ == "__main__":
    app.run(debug=True, port=5001)
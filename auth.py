from flask import url_for, redirect, request, flash
import sqlite3

def authorize_sign_up(password, confirmpassword, email):
    con = sqlite3.connect('users.db')
    cur = con.cursor()
    log = False
    if password == confirmpassword:
        log = True
    else:
        flash('Passwords do not match', 'error')
    cur.execute('''SELECT email FROM Authenticated_users''')
    logged_emails = [row[0] for row in cur.fetchall()]  # Extract email from each tuple
    con.commit()
    con.close()
    if email in logged_emails:
        flash('Email is already associated with an account', 'error')
        log = False
    return log
def authenticate_login(password, email):
    con = sqlite3.connect('users.db')
    cur = con.cursor()
    cur.execute('''SELECT * FROM Authenticated_users WHERE email = ? AND password = ?''', (email, password))
    user = cur.fetchone()
    con.close()
    if user:
        return True
    else:
        flash('Invalid credentials', 'error')
        return False
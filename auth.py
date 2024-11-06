from flask import flash
import sqlite3
import bcrypt
import hashlib

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
    
    cur.execute('''SELECT password FROM Authenticated_users WHERE email = ?''', (email,))
    stored_hash = cur.fetchone()
    con.close()
    
    if stored_hash:
        # Compare hashed password
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash[0].encode('utf-8')):
            return True
        else:
            flash('Invalid credentials', 'error')
            return False
    else:
        flash('Email not found', 'error')
        return False

def authorize_admin(password, email):
    paskey = hashlib.sha256('@FABRIC'.encode()).hexdigest()
    
    # For admin authorization, it's better to compare hashes rather than storing plain text passwords
    if bcrypt.checkpw(password.encode('utf-8'), paskey.encode('utf-8')) and email == 'cpal.teams@gmail.com':
        return True
    else:
        flash('Admin authentication failed', 'error')
        return False

def create_user(email, password):
    # Hash password before saving it
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    con = sqlite3.connect('users.db')
    cur = con.cursor()

    try:
        cur.execute('''INSERT INTO Authenticated_users (email, password) VALUES (?, ?)''', (email, hashed_pw))
        con.commit()
    except sqlite3.IntegrityError:
        flash('Email is already registered', 'error')
    finally:
        con.close()

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

        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return render_template('sign_up.html', error="Email already registered")

        # Create and save the new user
        new_user = User(name=name, email=email, password=hashed_password, is_verified=False, has_agreed_terms=False, has_completed_onboarding=False)
        db.session.add(new_user)
        db.session.commit()

        # Generate a verification code
        verifycode = random.randint(100000, 999999)
        session['email'] = email
        session['code'] = verifycode

        # Send the verification code via email
        send_email(email, verifycode)

        # Redirect to verification page
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

from flask import render_template
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(recipient_email, verifycode):
    sender_email = "your_email@example.com"
    sender_password = "your_password"  # Securely handle passwords!

    # Render the email template
    email_content = render_template('verification_email.html', verifycode=verifycode, year=2024)

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = "CPAL Verification Code"

    msg.attach(MIMEText(email_content, 'html'))

    try:
        with smtplib.SMTP('smtp.example.com', 587) as server:  # Update with your SMTP server
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
            print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

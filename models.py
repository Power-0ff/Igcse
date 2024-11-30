from db import db


class Img(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    img = db.Column(db.Text, unique=True, nullable=False)
    name = db.Column(db.Text, nullable=False)
    category = db.Column(db.Text(50), nullable=False)
    subject = db.Column(db.Text(50), nullable=False)
    tags = db.Column(db.Text, nullable = True)
    mimetype = db.Column(db.Text, nullable=False)
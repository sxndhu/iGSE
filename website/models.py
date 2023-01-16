from . import db
from flask_login import UserMixin 


class Customer(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(100), unique = True)
    password = db.Column(db.String(50))
    first_name = db.Column(db.String(100))
    address = db.Column(db.String(150))
    proptery_type = db.Column(db.String(50))
    number_of_bedrooms = db.Column(db.Integer)
    voucher = db.Column(db.String(8), unique = True)


class Admin(db.Model, UserMixin):
    admin_email = db.Column(db.String(100), primary_key = True)
    admin_password = db.Column(db.String(50))


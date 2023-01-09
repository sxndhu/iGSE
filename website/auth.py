from flask import Blueprint, render_template, request , flash, redirect, url_for
from .models import Customer
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth', __name__)

@auth.route('/login', methods = ['GET','POST'])
def login():
    return render_template("login.html")


@auth.route('/logout')
def logout():
    return render_template("login.html")


@auth.route('/sign-up', methods = ['GET','POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        address = request.form.get('address')
        proptery_type = request.form.get('property_type')
        number_of_bedrooms = request.form.get('number_of_bedrooms')
        voucher = request.form.get('voucher')

        custo = Customer.query.filter_by(email=email).first()
        if custo:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_customer = Customer(email = email, first_name = first_name, password = generate_password_hash(password1, method = 'sha256'), address = address, proptery_type =proptery_type, number_of_bedrooms = number_of_bedrooms, voucher = voucher)
            db.session.add(new_customer)
            db.session.commit()
            login_user(new_customer, remember=True)
            flash('Account created!',category = 'success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", custo=current_user)

@auth.route('/admin')
def admin():
    return "Admin"
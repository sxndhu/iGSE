from flask import Blueprint, render_template, request , flash, redirect, url_for
from .models import Customer, Admin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth', __name__)

@auth.route('/login', methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        custo = Customer.query.filter_by(email=email).first()
        if custo:
            if check_password_hash(custo.password, password):
                flash('Logged in successfully!', category = 'success')
                login_user(custo, remember = True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password. Try again.', category = 'error')
        else:
            flash('Email does not exist, create an account.', category = 'error')

    return render_template("login.html", custo=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


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


@auth.route('/admin_login', methods = ['GET','POST'])
def admin_login():
    admin_email = 'gse@shangrila.gov.un'
    admin_password = 'gse@energy'

    admin_exist = Admin.query.filter_by(admin_email = admin_email).first()
    if not admin_exist:
        new_admin = Admin(admin_email = admin_email, admin_password = generate_password_hash(admin_password, method = 'sha256'))
        db.session.add(new_admin)
        db.session.commit()

    if request.method == 'POST':
        email_input = request.form.get('admin_email')
        password_input = request.form.get('admin_password')

        if email_input != admin_email:
            flash('Email not authorized. Not admin.', category = 'error')
        elif password_input != admin_password:
            flash('Password incorrect.', category = 'error')
        else:
            return render_template("admin_home.html")

    return render_template("admin_login.html")
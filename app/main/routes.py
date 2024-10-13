from flask import render_template, request, redirect, url_for, flash, session
from app.main import bp
from app.util.secure import KeyController
from app.models.user import User
from app.extensions import db

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

class UserForm(FlaskForm):
    email = StringField('E-Mail', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

@bp.route('/')
def index():
    return render_template('index.html')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    form = UserForm()
    if form.validate_on_submit():
        # Process user data here (e.g., save to database)
        email = form.email.data
        password = form.password.data

        kc = KeyController(email, password)
        
        new_user = User(
            email=email,
            passwordhash=kc.master_password_hash.hex()
            )
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('main.success'))
    return render_template('register.html', form=form)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    form = UserForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Check to see if the user already exists
        user = User.query.filter_by(email=email).first()
        kc = KeyController(email, password)

        if user and kc.valid_master_password_hash(user.passwordhash):
            flash('Logged in successfully!', 'success')
            return redirect(url_for('main.login'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('main.login'))
    return render_template('login.html', form=form)


@bp.route('/success')
def success():
    return "User created successfully!"
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo

class UserForm(FlaskForm):
    email = StringField(validators=[DataRequired()])
    name = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    password_verify = PasswordField(validators=[DataRequired(),
        EqualTo('password', message='Passwords must match.')]
    )

class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
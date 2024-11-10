from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

class UserForm(FlaskForm):
    email = StringField(validators=[DataRequired()])
    name = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])

class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
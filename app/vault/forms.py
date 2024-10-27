from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired

class CredentialCreateForm(FlaskForm):
    name = StringField(validators=[DataRequired()])
    username = StringField(validators=[DataRequired()])
    ciphertext = PasswordField(validators=[DataRequired()])
    website = StringField(validators=[DataRequired()])

class CredentialUpdateForm(FlaskForm):
    name = StringField(validators=[DataRequired()])
    username = StringField(validators=[DataRequired()])
    ciphertext = StringField(validators=[DataRequired()])
    website = StringField(validators=[DataRequired()])
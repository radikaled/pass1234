import base64

from flask import render_template, redirect, url_for, flash
from sqlalchemy.exc import NoResultFound

from app.main import bp
from app.util.secure import KeyController
from app.models.user import User
from app.models.vault import Vault
from app.extensions import db
from app.main.forms import UserForm

# Lambda shorthand for base64 encoding
b64encode_str = lambda data: base64.b64encode(data).decode('utf-8')

# Lambda shorthand for base64 decoding
b64decode_str = lambda data: base64.b64decode(data)

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

        # Begin creating the new user
        new_user = User(
            email=email,
            master_password_hash=(b64encode_str(kc.master_password_hash))
        )
        db.session.add(new_user)
        db.session.flush()  # Push pending changes without committing

        # Generate the user's protected symmetric key
        key_artifacts = kc.generate_protected_symmetric_key()

        # Create the user's vault instance
        new_vault = Vault(
            user_id=new_user.id,
            iv=b64encode_str(key_artifacts.iv),
            protected_key=b64encode_str(key_artifacts.protected_key),
            hmac_signature=b64encode_str(key_artifacts.hmac_signature)
        )
        db.session.add(new_vault)
        
        # New user creation complete
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
        try:
            user = db.session.execute(
                db.select(User).where(User.email == email)
            ).scalar_one()
        except NoResultFound:
            # Redirect to registration page
            return redirect(url_for('main.register'))
        
        kc = KeyController(email, password)

        if user and kc.verify_master_password_hash(
            b64decode_str(user.master_password_hash)
        ):
            flash('Logged in successfully!', 'success')
            return redirect(url_for('main.login'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('main.login'))
    return render_template('login.html', form=form)


@bp.route('/success')
def success():
    return "User created successfully!"
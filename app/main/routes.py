import base64

from flask import render_template, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.exc import NoResultFound

from app.main import bp
from app.util.secure import KeyController
from app.util.cipher_utils import decrypt, encrypt
from app.models.user import User
from app.models.vault import Vault
from app.extensions import db
from app.main.forms import UserForm, LoginForm

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
        name = form.name.data
        password = form.password.data

        kc = KeyController(email, password)

        # Begin creating the new user
        new_user = User(
            email=email,
            name=name,
            master_password_hash=(b64encode_str(kc.get_master_password_hash()))
        )
        db.session.add(new_user)
        db.session.flush()  # Push pending changes without committing

        # Generate the user's protected symmetric key
        key_artifacts = kc.generate_protected_symmetric_key()

        decrypted_key = kc.unlock_vault(
            key_artifacts.iv,
            key_artifacts.protected_key,
            key_artifacts.hmac_signature
        )

        encryption_key = decrypted_key[:32]
        hmac_key = decrypted_key[32:]

        # Generate the user's RSA public-key pair
        rsa_artifacts = kc.generate_asymmetric_keypair(encryption_key, hmac_key)

        # Create the user's vault instance
        new_vault = Vault(
            user_id=new_user.id,
            iv=b64encode_str(key_artifacts.iv),
            protected_key=b64encode_str(key_artifacts.protected_key),
            hmac_signature=b64encode_str(key_artifacts.hmac_signature),
            rsa_private_key_iv=b64encode_str(rsa_artifacts.iv),
            rsa_private_key=b64encode_str(rsa_artifacts.rsa_private_key_pem),
            rsa_public_key=b64encode_str(rsa_artifacts.rsa_public_key_pem),
            rsa_private_key_hmac_signature=b64encode_str(
                rsa_artifacts.hmac_signature
            )
        )
        db.session.add(new_vault)
        
        # New user creation complete
        db.session.commit()

        return redirect(url_for('main.success'))
    return render_template('register.html', form=form)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
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
        
        # User's first vault
        vault = user.vaults[0]
        
        kc = KeyController(email, password)

        if user and kc.verify_master_password_hash(
            b64decode_str(user.master_password_hash)
        ):
            
            protected_key = kc.unlock_vault(
                b64decode_str(vault.iv),
                b64decode_str(vault.protected_key),
                b64decode_str(vault.hmac_signature)
            )
            
            session['_aes_key'] = protected_key[:32]
            session['_hmac_key'] = protected_key[32:]
            
            # Login
            login_user(user)
            
            return redirect(url_for('main.profile'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('main.login'))
    return render_template('login.html', form=form)

@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@bp.route('/profile')
@login_required
def profile():
    print(f'{session}')
    return render_template('profile.html', name=current_user.email)

@bp.route('/success')
def success():
    return "User created successfully!"
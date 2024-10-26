import base64

from flask import render_template, redirect, url_for, flash, session
from flask_login import login_user, login_required, current_user
from sqlalchemy.exc import NoResultFound

from app.vault import bp
from app.util.cipher_utils import decrypt, encrypt, generate_hmac
from app.models.credential import Credential
from app.extensions import db
from app.vault.forms import CredentialForm

# Lambda shorthand for base64 encoding
b64encode_str = lambda data: base64.b64encode(data).decode('utf-8')

# Lambda shorthand for base64 decoding
b64decode_str = lambda data: base64.b64decode(data)

@bp.route('/vault')
@login_required
def index():
    # For some reason this doesn't work right now but will check later
    # credentials = current_user.vaults[0].credentials
    
    # For now this works OK
    credentials = db.session.execute(
        db.select(Credential).where(
            Credential.vault_id == current_user.vaults[0].id
        )
    ).scalars().all()

    for credential in credentials:
        credential.ciphertext = decrypt(
            b64decode_str(credential.iv),
            b64decode_str(credential.ciphertext),
            session['_aes_key']
        ).decode()
    
    return render_template('vault.html', credentials=credentials)

@bp.route('/vault/create/', methods=('GET', 'POST'))
@login_required
def create():
    form = CredentialForm()
    if form.validate_on_submit():
        # Process credential data here (e.g., save to database)
        name = form.name.data
        username = form.username.data
        password = form.password.data
        website = form.website.data

        iv, ciphertext = encrypt(password.encode(), session['_aes_key'])
        hmac_signature = generate_hmac(
            session['_hmac_key'],
            iv + ciphertext
        )

        # Begin creating the new credential 
        new_credential = Credential(
            vault_id=current_user.vaults[0].id,
            name=name,
            username=username,
            ciphertext=b64encode_str(ciphertext),
            iv=b64encode_str(iv),
            hmac_signature=b64encode_str(hmac_signature),
            website=website
        )
        db.session.add(new_credential)
        db.session.commit()

        return redirect(url_for('vault.index'))
    return render_template('create.html', form=form)
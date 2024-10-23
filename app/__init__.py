from flask import Flask

from config import Config
from app.extensions import db
from app.extensions import lm
from app.models.user import User

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Flask extensions here
    db.init_app(app)    # Database

    lm.login_view = 'main.login'
    lm.init_app(app)

    # Register blueprints here
    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    # Create tables that do not already exist in the database
    # Effectively database init
    with app.app_context():
        db.create_all()

    @lm.user_loader
    def load_user(user_id):
        return db.session.get(User, user_id)

    return app
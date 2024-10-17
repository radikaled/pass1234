from flask import Flask

from config import Config
from app.extensions import db

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Flask extensions here
    db.init_app(app)    # Database

    # Register blueprints here
    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    # Create tables that do not already exist in the database
    # Effectively database init
    with app.app_context():
        db.create_all()

    @app.route('/test/')
    def test_page():
        return '<h1>Testing the Flask Application Factory Pattern</h1>'

    return app
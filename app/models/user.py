from app.extensions import db
from sqlalchemy.sql import func

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    passwordhash = db.Column(db.String(255), unique=True, nullable=False)
    datecreated = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now()
        )

    def __repr__(self):
        return f'<User "{self.email}">'
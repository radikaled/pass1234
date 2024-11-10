from typing import List
from datetime import datetime

from flask_login import UserMixin
from sqlalchemy import DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.extensions import db

class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(unique=True)
    name: Mapped[str]
    master_password_hash: Mapped[str] = mapped_column(unique=True)
    date_created: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now()   # Let sqlite set the current timestamp
    )
    date_modified: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )
    vaults: Mapped[List["Vault"]] = relationship(back_populates="user")

    def __repr__(self):
        return f'<User "{self.email}">'
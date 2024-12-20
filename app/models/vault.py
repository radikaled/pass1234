from typing import List
from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.extensions import db
from app.models.user import User
from app.models.credential import Credential

class Vault(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    iv: Mapped[str] = mapped_column(unique=True)
    protected_key: Mapped[str] = mapped_column(unique=True)
    hmac_signature: Mapped[str] = mapped_column(unique=True)
    rsa_private_key_iv: Mapped[str] = mapped_column(unique=True)
    rsa_private_key: Mapped[str] = mapped_column(unique=True)
    rsa_public_key: Mapped[str] = mapped_column(unique=True)
    rsa_private_key_hmac_signature: Mapped[str] = mapped_column(unique=True)
    date_created: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now()   # Let sqlite set the current timestamp
    )
    date_modified: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )
    user: Mapped["User"] = relationship(back_populates="vaults")
    credentials: Mapped[List["Credential"]] = relationship(back_populates="vault")

    def __repr__(self):
        return f'<Vault "{self.id}">'
from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.extensions import db

class Credential(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    vault_id: Mapped[int] = mapped_column(ForeignKey("vault.id"))
    name: Mapped[str]
    username: Mapped[str]
    website: Mapped[str]
    iv: Mapped[str] = mapped_column(unique=True)
    ciphertext: Mapped[str] = mapped_column(unique=True)
    hmac_signature: Mapped[str] = mapped_column(unique=True)
    date_created: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now()   # Let sqlite set the current timestamp
    )
    date_modified: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )
    vault: Mapped["Vault"] = relationship(back_populates="credentials")

    def __repr__(self):
        return f'<Credential "{self.id}">'
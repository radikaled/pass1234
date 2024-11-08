from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.extensions import db
from app.models.credential import Credential

class SharedCredential(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    credential_id: Mapped[int] = mapped_column(ForeignKey("credential.id"))
    subject_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    ciphertext: Mapped[str] = mapped_column(unique=True)
    date_created: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now()   # Let sqlite set the current timestamp
    )
    date_modified: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )
    credential: Mapped["Credential"] = relationship(
        back_populates="shared_credentials"
    )

    def __repr__(self):
        return f'<Credential "{self.id}">'
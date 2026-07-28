from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime

from app.database.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    target = Column(String, nullable=False)

    scan_type = Column(String, default="Nmap")

    status = Column(String, default="Pending")

    output = Column(Text)

    created_at = Column(DateTime, default=datetime.utcnow)
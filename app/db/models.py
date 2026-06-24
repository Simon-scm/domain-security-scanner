from sqlalchemy import Column, String, DateTime, Integer, Text
from sqlalchemy.sql import func
from app.db.session import Base

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(String, primary_key=True)
    domain = Column(String, nullable=False)
    input_sanitized = Column(String, nullable=False)
    status = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    score = Column(Integer, nullable=True)
    result_json = Column(Text, nullable=True)


"""
SQLAlchemy models for tracking Devin sessions.
"""

from sqlalchemy import Column, Integer, String

from app.database import Base


class SessionRecord(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    devin_session_id = Column(String, unique=True, nullable=False)
    devin_session_url = Column(String, nullable=False)
    github_issue_number = Column(Integer, nullable=False)
    github_issue_title = Column(String, nullable=False)
    github_repo = Column(String, nullable=False)
    status = Column(String, nullable=False, default="running")
    pull_request_url = Column(String, nullable=True)
    created_at = Column(Integer, nullable=False)
    severity_score = Column(Integer, nullable=True, default=0)
    severity_label = Column(String, nullable=True, default="Low")
    vulnerability_count = Column(Integer, nullable=True, default=1)
    logs = Column(String, nullable=True, default="[]")  # JSON array of log entries

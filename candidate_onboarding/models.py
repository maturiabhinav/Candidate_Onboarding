from datetime import datetime
from candidate_onboarding import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    employee = db.relationship("Employee", backref="user", uselist=False, cascade="all, delete-orphan")

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True, nullable=False)
    department = db.Column(db.String(100))
    profile_image_url = db.Column(db.String(500))
    s3_key = db.Column(db.String(500))  # S3 object key for profile image
    is_submitted = db.Column(db.Boolean, default=False)
    submitted_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.now)

    documents = db.relationship("Document", backref="employee", lazy=True, cascade="all, delete-orphan")

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey("employee.id", ondelete="CASCADE"), nullable=False)
    file_url = db.Column(db.String(500))  # S3 URI
    download_url = db.Column(db.String(500))  # Presigned URL
    s3_key = db.Column(db.String(500))  # S3 object key
    file_name = db.Column(db.String(300))
    file_type = db.Column(db.String(50))
    is_approved = db.Column(db.Boolean, default=False)
    reviewed_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    reviewed_at = db.Column(db.DateTime)
    uploaded_at = db.Column(db.DateTime, default=datetime.now)
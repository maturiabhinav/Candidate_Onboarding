from datetime import datetime
from candidate_onboarding import db
from flask_login import UserMixin
import json

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
    s3_key = db.Column(db.String(500))
    is_submitted = db.Column(db.Boolean, default=False)
    submitted_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.now)
    is_active = db.Column(db.Boolean, default=True)

    # New comprehensive fields
    father_name = db.Column(db.String(150))
    address = db.Column(db.Text)
    permanent_address = db.Column(db.Text)
    blood_group = db.Column(db.String(10))
    mobile = db.Column(db.String(15))
    emergency_contact_name = db.Column(db.String(150))
    emergency_contact_number = db.Column(db.String(15))
    
    # Education details (stored as JSON for flexibility)
    education_details = db.Column(db.Text)  # JSON string
    
    # Internship details (stored as JSON)
    internship_details = db.Column(db.Text)  # JSON string
    
    # Experience details (stored as JSON)
    experience_details = db.Column(db.Text)  # JSON string
    
    # Other details (stored as JSON)
    other_details = db.Column(db.Text)  # JSON string

    documents = db.relationship("Document", backref="employee", lazy=True, cascade="all, delete-orphan")

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey("employee.id", ondelete="CASCADE"), nullable=False)
    file_url = db.Column(db.String(500))
    download_url = db.Column(db.String(500))
    s3_key = db.Column(db.String(500))
    file_name = db.Column(db.String(300))
    file_type = db.Column(db.String(50))
    document_category = db.Column(db.String(100))  # 'education', 'identity', 'bank', etc.
    document_type = db.Column(db.String(100))  # 'ssc', 'aadhar', 'pan', etc.
    is_approved = db.Column(db.Boolean, default=False)
    reviewed_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    reviewed_at = db.Column(db.DateTime)
    uploaded_at = db.Column(db.DateTime, default=datetime.now)


from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from candidate_onboarding.models import User, Employee, Document
from candidate_onboarding import db
from candidate_onboarding.utils import send_email, generate_token, verify_token, get_s3_client, upload_to_s3
import os
import uuid
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

onboarding_bp = Blueprint('onboarding', __name__)

# Configure allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'}
ALLOWED_IMAGES = {'jpg', 'jpeg', 'png'}

def allowed_file(filename, file_type='document'):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    if file_type == 'image':
        return ext in ALLOWED_IMAGES
    return ext in ALLOWED_EXTENSIONS

# ==================== AUTHENTICATION ROUTES ====================

@onboarding_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if getattr(current_user, 'is_admin', False):
            return redirect(url_for('onboarding.admin_dashboard'))
        return redirect(url_for('onboarding.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('onboarding.admin_dashboard'))
            else:
                return redirect(url_for('onboarding.dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')

@onboarding_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('onboarding.login'))

# ==================== PASSWORD RESET ROUTES ====================

@onboarding_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.join(Employee).filter(Employee.email == email).first()
        
        if user:
            token = generate_token(user.id, 'reset')
            reset_url = url_for('onboarding.reset_password', token=token, _external=True)
            
            email_template = f"""
            <h3>Password Reset Request</h3>
            <p>Click the link below to reset your password:</p>
            <a href="{reset_url}">Reset Password</a>
            <p>This link expires in 24 hours.</p>
            """
            
            send_email("Password Reset Request", email, email_template)
            flash('Password reset link sent to your email.', 'success')
        else:
            flash('Email not found.', 'error')
    
    return render_template('forgot_password.html')

@onboarding_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user_id = verify_token(token, 'reset')
    if not user_id:
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('onboarding.forgot_password'))
    
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('onboarding.forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('onboarding.reset_password', token=token))
        
        user.password = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Password updated successfully! Please login.', 'success')
        return redirect(url_for('onboarding.login'))
    
    return render_template('reset_password.html', token=token)



# ==================== ADMIN ROUTES ====================

@onboarding_bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    employees = Employee.query.all()
    return render_template('admin_dashboard.html', employees=employees)




@onboarding_bp.route('/admin/documents')
@login_required
def admin_documents():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    
    pending_docs = Document.query.filter_by(is_approved=False).all()
    approved_docs = Document.query.filter_by(is_approved=True).all()
    
    return render_template('admin_documents.html', 
                         pending_docs=pending_docs, 
                         approved_docs=approved_docs)

@onboarding_bp.route('/admin/approve_document/<int:doc_id>')
@login_required
def approve_document(doc_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    
    document = Document.query.get_or_404(doc_id)
    document.is_approved = True
    document.reviewed_by = current_user.id
    document.reviewed_at = datetime.utcnow()
    db.session.commit()
    
    flash(f'Document {document.file_name} approved!', 'success')
    return redirect(url_for('onboarding.admin_documents'))

@onboarding_bp.route('/admin/reject_document/<int:doc_id>')
@login_required
def reject_document(doc_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    
    document = Document.query.get_or_404(doc_id)
    
    # Delete from S3
    try:
        s3_client = get_s3_client()
        s3_client.delete_object(
            Bucket=os.getenv('AWS_S3_BUCKET'),
            Key=document.s3_key
        )
    except ClientError as e:
        flash(f'Error deleting file from S3: {str(e)}', 'error')
    
    # Delete from database
    db.session.delete(document)
    db.session.commit()
    
    flash('Document rejected and deleted.', 'success')
    return redirect(url_for('onboarding.admin_documents'))

# ==================== EMPLOYEE ROUTES ====================

@onboarding_bp.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('onboarding.admin_dashboard'))
    
    employee = Employee.query.filter_by(user_id=current_user.id).first()
    if not employee:
        flash('Employee record not found.', 'error')
        return redirect(url_for('onboarding.logout'))
    
    docs = Document.query.filter_by(employee_id=employee.id).all()
    return render_template('dashboard.html', employee=employee, docs=docs)

@onboarding_bp.route('/profile_setup', methods=['GET', 'POST'])
@login_required
def profile_setup():
    if current_user.is_admin:
        return redirect(url_for('onboarding.admin_dashboard'))
    
    employee = Employee.query.filter_by(user_id=current_user.id).first()
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        email = request.form.get('email','').strip()
        department = request.form.get('department','').strip()
        if not name or not email or not department:
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('onboarding.profile_setup'))
        employee.name = name
        employee.email = email
        employee.department = department
        employee.is_submitted = True
        employee.submitted_at = datetime.utcnow()
        db.session.commit()
        flash('Your profile has been submitted successfully!', 'success')
        return redirect(url_for('onboarding.dashboard'))
    return render_template('profile_setup.html', employee=employee)

@onboarding_bp.route('/reset_profile')
@login_required
def reset_profile():
    if current_user.is_admin:
        return redirect(url_for('onboarding.admin_dashboard'))
    
    employee = Employee.query.filter_by(user_id=current_user.id).first()
    if employee:
        # Delete profile image from S3
        if employee.s3_key:
            try:
                s3_client = get_s3_client()
                s3_client.delete_object(
                    Bucket=os.getenv('AWS_S3_BUCKET'),
                    Key=employee.s3_key
                )
            except ClientError:
                pass
        
        # Delete documents from S3 and database
        documents = Document.query.filter_by(employee_id=employee.id).all()
        for doc in documents:
            try:
                s3_client = get_s3_client()
                s3_client.delete_object(
                    Bucket=os.getenv('AWS_S3_BUCKET'),
                    Key=doc.s3_key
                )
            except ClientError:
                pass
            db.session.delete(doc)
        
        # Reset employee data
        employee.name = None
        employee.department = None
        employee.profile_image_url = None
        employee.s3_key = None
        employee.is_submitted = False
        employee.submitted_at = None
        
        db.session.commit()
    
    flash('Your profile has been reset. You can start over.', 'info')
    return redirect(url_for('onboarding.profile_setup'))

# ==================== FILE UPLOAD ROUTES ====================

@onboarding_bp.route('/upload_document', methods=['POST'])
@login_required
def upload_document():
    if current_user.is_admin:
        flash('Admins cannot upload documents.', 'error')
        return redirect(url_for('onboarding.admin_dashboard'))
    
    employee = Employee.query.filter_by(user_id=current_user.id).first()
    if not employee:
        flash('Employee record not found.', 'error')
        return redirect(url_for('onboarding.logout'))
    
    if 'document' not in request.files:
        flash('No file selected.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    
    file = request.files['document']
    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    
    if file and allowed_file(file.filename):
        # Upload to S3
        upload_result = upload_to_s3(file, "documents", employee.id)
        
        if upload_result:
            new_document = Document(
                employee_id=employee.id,
                file_url=upload_result['file_url'],
                download_url=upload_result['download_url'],
                s3_key=upload_result['s3_key'],
                file_name=secure_filename(file.filename),
                file_type=file.filename.rsplit('.', 1)[1].lower(),
                is_approved=False
            )
            db.session.add(new_document)
            db.session.commit()
            
            flash(f'Document {file.filename} uploaded successfully! Waiting for admin approval.', 'success')
    else:
        flash('Invalid file type. Allowed: pdf, doc, docx, jpg, jpeg, png', 'error')
    
    return redirect(url_for('onboarding.dashboard'))

@onboarding_bp.route('/upload_profile_image', methods=['POST'])
@login_required
def upload_profile_image():
    if current_user.is_admin:
        flash('Admins cannot upload profile images.', 'error')
        return redirect(url_for('onboarding.admin_dashboard'))
    
    employee = Employee.query.filter_by(user_id=current_user.id).first()
    if not employee:
        flash('Employee record not found.', 'error')
        return redirect(url_for('onboarding.logout'))
    
    if 'profile_image' not in request.files:
        flash('No image selected.', 'error')
        return redirect(url_for('onboarding.profile_setup'))
    
    file = request.files['profile_image']
    if file.filename == '':
        flash('No image selected.', 'error')
        return redirect(url_for('onboarding.profile_setup'))
    
    if file and allowed_file(file.filename, 'image'):
        # Delete old profile image from S3 if exists
        if employee.s3_key:
            try:
                s3_client = get_s3_client()
                s3_client.delete_object(
                    Bucket=os.getenv('AWS_S3_BUCKET'),
                    Key=employee.s3_key
                )
            except ClientError:
                pass  # Ignore if file doesn't exist
        
        # Upload new image to S3
        upload_result = upload_to_s3(file, "profile_images", employee.id)
        
        if upload_result:
            employee.profile_image_url = upload_result['download_url']
            employee.s3_key = upload_result['s3_key']
            db.session.commit()
            
            flash('Profile image updated successfully!', 'success')
    else:
        flash('Invalid image type. Allowed: jpg, jpeg, png', 'error')
    
    return redirect(url_for('onboarding.profile_setup'))

@onboarding_bp.route('/download_document/<int:doc_id>')
@login_required
def download_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    
    # Check permissions
    if not current_user.is_admin and document.employee.user_id != current_user.id:
        flash('Access denied.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    
    # Generate new presigned URL (since old one might be expired)
    try:
        s3_client = get_s3_client()
        new_download_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': os.getenv('AWS_S3_BUCKET'),
                'Key': document.s3_key
            },
            ExpiresIn=3600
        )
        
        # Update the download URL in database
        document.download_url = new_download_url
        db.session.commit()
        
        return redirect(new_download_url)
    except ClientError as e:
        flash('Error generating download link.', 'error')
        return redirect(url_for('onboarding.dashboard'))

@onboarding_bp.route('/delete_document/<int:doc_id>')
@login_required
def delete_document(doc_id):
    if current_user.is_admin:
        flash('Admins cannot delete employee documents.', 'error')
        return redirect(url_for('onboarding.admin_dashboard'))
    
    employee = Employee.query.filter_by(user_id=current_user.id).first()
    document = Document.query.filter_by(id=doc_id, employee_id=employee.id).first()
    
    if document:
        # Delete from S3
        try:
            s3_client = get_s3_client()
            s3_client.delete_object(
                Bucket=os.getenv('AWS_S3_BUCKET'),
                Key=document.s3_key
            )
        except ClientError as e:
            flash(f'Error deleting file from S3: {str(e)}', 'error')
        
        # Delete from database
        db.session.delete(document)
        db.session.commit()
        flash('Document deleted successfully!', 'success')
    else:
        flash('Document not found.', 'error')
    
    return redirect(url_for('onboarding.dashboard'))

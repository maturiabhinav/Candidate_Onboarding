from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from candidate_onboarding.models import User, Employee, Document
from candidate_onboarding import db
from candidate_onboarding.utils import send_email, generate_token, verify_token, get_s3_client, upload_to_s3
import os
import uuid
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError
import json

onboarding_bp = Blueprint('onboarding', __name__)

# Configure allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'}
ALLOWED_IMAGES = {'jpg', 'jpeg', 'png'}

# Utility Functions
def allowed_file(filename, file_type='document'):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    if file_type == 'image':
        return ext in ALLOWED_IMAGES
    return ext in ALLOWED_EXTENSIONS

# UPLOAD HANDLER FOR MULTIPLE DOCUMENT CATEGORIES
def handle_file_uploads(request, employee):
    """Handle multiple file uploads for different document categories"""
    try:
        uploaded_files = []
        
        # Education documents
        education_files = {
            'ssc': request.files.get('sscDocument'),
            'intermediate': request.files.get('interDocument'),
            'graduation': request.files.get('gradDocument'),
            'post_graduation': request.files.get('postGradDocument')
        }
        
        for doc_type, file in education_files.items():
            if file and file.filename:
                upload_result = upload_to_s3(file, f"education/{doc_type}", employee.id)
                if upload_result:
                    document = Document(
                        employee_id=employee.id,
                        file_url=upload_result['file_url'],
                        download_url=upload_result['download_url'],
                        s3_key=upload_result['s3_key'],
                        file_name=secure_filename(file.filename),
                        file_type=file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'bin',
                        document_category='education',
                        document_type=doc_type,
                        is_approved=False
                    )
                    db.session.add(document)
                    uploaded_files.append(file.filename)
        
        # Identity documents
        identity_files = {
            'aadhar': request.files.get('aadharDoc'),
            'pan': request.files.get('panDoc'),
            'voter_id': request.files.get('voterDoc'),
            'driving_license': request.files.get('licenceDoc')
        }
        
        for doc_type, file in identity_files.items():
            if file and file.filename:
                upload_result = upload_to_s3(file, f"identity/{doc_type}", employee.id)
                if upload_result:
                    document = Document(
                        employee_id=employee.id,
                        file_url=upload_result['file_url'],
                        download_url=upload_result['download_url'],
                        s3_key=upload_result['s3_key'],
                        file_name=secure_filename(file.filename),
                        file_type=file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'bin',
                        document_category='identity',
                        document_type=doc_type,
                        is_approved=False
                    )
                    db.session.add(document)
                    uploaded_files.append(file.filename)
        
        # Bank documents
        bank_file = request.files.get('bankDoc')
        if bank_file and bank_file.filename:
            upload_result = upload_to_s3(bank_file, "bank", employee.id)
            if upload_result:
                document = Document(
                    employee_id=employee.id,
                    file_url=upload_result['file_url'],
                    download_url=upload_result['download_url'],
                    s3_key=upload_result['s3_key'],
                    file_name=secure_filename(bank_file.filename),
                    file_type=bank_file.filename.rsplit('.', 1)[1].lower() if '.' in bank_file.filename else 'bin',
                    document_category='bank',
                    document_type='bank_statement',
                    is_approved=False
                )
                db.session.add(document)
                uploaded_files.append(bank_file.filename)
        
        # Internship documents
        internship_file = request.files.get('internshipOffer')
        if internship_file and internship_file.filename:
            upload_result = upload_to_s3(internship_file, "internship", employee.id)
            if upload_result:
                document = Document(
                    employee_id=employee.id,
                    file_url=upload_result['file_url'],
                    download_url=upload_result['download_url'],
                    s3_key=upload_result['s3_key'],
                    file_name=secure_filename(internship_file.filename),
                    file_type=internship_file.filename.rsplit('.', 1)[1].lower() if '.' in internship_file.filename else 'bin',
                    document_category='internship',
                    document_type='certificate',
                    is_approved=False
                )
                db.session.add(document)
                uploaded_files.append(internship_file.filename)
        
        # Experience documents
        experience_files = {
            'offer_letter': request.files.get('experienceOffer'),
            'payslip': request.files.get('experiencePayslip'),
            'relieving_letter': request.files.get('experienceRelieving')
        }
        
        for doc_type, file in experience_files.items():
            if file and file.filename:
                upload_result = upload_to_s3(file, f"experience/{doc_type}", employee.id)
                if upload_result:
                    document = Document(
                        employee_id=employee.id,
                        file_url=upload_result['file_url'],
                        download_url=upload_result['download_url'],
                        s3_key=upload_result['s3_key'],
                        file_name=secure_filename(file.filename),
                        file_type=file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'bin',
                        document_category='experience',
                        document_type=doc_type,
                        is_approved=False
                    )
                    db.session.add(document)
                    uploaded_files.append(file.filename)
        
        print(f"✅ Successfully uploaded {len(uploaded_files)} files: {uploaded_files}")
        return True
        
    except Exception as e:
        print(f"❌ Error handling file uploads: {e}")
        return False

# ==================== AUTHENTICATION ROUTES ====================

@onboarding_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if getattr(current_user, 'is_admin', False):
            return redirect(url_for('onboarding.admin_dashboard'))
        return redirect(url_for('onboarding.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        
        if not email or not password:
            flash('Please enter both email and password', 'error')
            return redirect(url_for('onboarding.login'))
        
        # Find employee by email (case-insensitive)
        employee = Employee.query.filter(Employee.email.ilike(email)).first()
        if not employee:
            flash('Invalid email or password', 'error')
            return redirect(url_for('onboarding.login'))
        
        user = User.query.get(employee.user_id)
        
        # Check if employee is active
        if not employee.is_active:
            flash('Account is deactivated. Please contact administrator.', 'error')
            return redirect(url_for('onboarding.login'))
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('onboarding.admin_dashboard'))
            else:
                return redirect(url_for('onboarding.dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@onboarding_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('onboarding.login'))

# ==================== PASSWORD CHANGE ROUTES ====================

@onboarding_bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Verify current password
        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('onboarding.change_password'))
        
        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('onboarding.change_password'))
        
        # Check password strength (optional)
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return redirect(url_for('onboarding.change_password'))
        
        # Update password
        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Password updated successfully!', 'success')
        return redirect(url_for('onboarding.dashboard' if not current_user.is_admin else 'onboarding.admin_dashboard'))
    
    return render_template('change_password.html')

# ==================== ADMIN MANAGEMENT ROUTES ====================

@onboarding_bp.route('/admin/create_admin', methods=['GET', 'POST'])
@login_required
def create_admin():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','').strip()
        name = request.form.get('name','').strip()

        if not email or not password:
            flash('Email and password are required.', 'error')
            return redirect(url_for('onboarding.create_admin'))

        # Check if email already exists
        existing_employee = Employee.query.filter(Employee.email.ilike(email)).first()
        if existing_employee:
            flash('Email already exists.', 'error')
            return redirect(url_for('onboarding.create_admin'))

        # Create user with email as username
        hashed_pw = generate_password_hash(password)
        new_admin = User(username=email, password=hashed_pw, is_admin=True)
        db.session.add(new_admin)
        db.session.commit()

        # Create employee record
        new_employee = Employee(
            user_id=new_admin.id, 
            email=email, 
            name=name, 
            is_submitted=True,
            is_active=True
        )
        db.session.add(new_employee)
        db.session.commit()

        flash(f'Admin account created for {email}!', 'success')
        return redirect(url_for('onboarding.admin_dashboard'))

    return render_template('create_admin.html')

@onboarding_bp.route('/admin/inactive_employees')
@login_required
def inactive_employees():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    
    inactive_employees = Employee.query.filter_by(is_active=False).all()
    return render_template('inactive_employees.html', employees=inactive_employees)

# ==================== ADMIN ROUTES ====================

@onboarding_bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    
    # Only show active employees
    employees = Employee.query.filter_by(is_active=True).all()
    pending_docs = Document.query.filter_by(is_approved=False).order_by(Document.uploaded_at.desc()).limit(5).all()
    pending_count = Document.query.filter_by(is_approved=False).count()
    approved_count = Document.query.filter_by(is_approved=True).count()
    
    return render_template('admin_dashboard.html', 
                         employees=employees,
                         pending_docs=pending_docs,
                         pending_count=pending_count,
                         approved_count=approved_count)

# FIXED: Only one create_employee route
@onboarding_bp.route('/admin/create_employee', methods=['GET', 'POST'])
@login_required
def create_employee():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','').strip()
        
        if not email or not password:
            flash('Email and password are required.', 'error')
            return redirect(url_for('onboarding.create_employee'))

        # Check if email already exists (including inactive employees)
        existing_employee = Employee.query.filter(Employee.email.ilike(email)).first()
        if existing_employee:
            flash('Email already exists.', 'error')
            return redirect(url_for('onboarding.create_employee'))

        # Create user with email as username
        hashed_pw = generate_password_hash(password)
        new_user = User(username=email, password=hashed_pw, is_admin=False)
        db.session.add(new_user)
        db.session.commit()

        new_employee = Employee(user_id=new_user.id, email=email, is_active=True)
        db.session.add(new_employee)
        db.session.commit()

        flash(f'Employee account created for {email}!', 'success')
        return redirect(url_for('onboarding.admin_dashboard'))

    return render_template('create_employee.html')

@onboarding_bp.route('/admin/documents')
@login_required
def admin_documents():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    
    pending_docs = Document.query.filter_by(is_approved=False).order_by(Document.uploaded_at.desc()).all()
    approved_docs = Document.query.filter_by(is_approved=True).order_by(Document.reviewed_at.desc()).all()
    
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
    document.reviewed_at = datetime.now(timezone.utc)
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
        print(f"✅ Deleted from S3: {document.s3_key}")
    except ClientError as e:
        print(f"❌ S3 delete error: {e}")
        flash(f'Error deleting file from S3: {str(e)}', 'error')
    
    # Delete from database
    db.session.delete(document)
    db.session.commit()
    
    flash('Document rejected and deleted.', 'success')
    return redirect(url_for('onboarding.admin_documents'))

# Delete approved documents
@onboarding_bp.route('/admin/delete_approved_document/<int:doc_id>')
@login_required
def delete_approved_document(doc_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    
    document = Document.query.get_or_404(doc_id)
    
    if not document.is_approved:
        flash('Can only delete approved documents.', 'error')
        return redirect(url_for('onboarding.admin_documents'))

    # Delete from S3
    try:
        s3_client = get_s3_client()
        s3_client.delete_object(
            Bucket=os.getenv('AWS_S3_BUCKET'),
            Key=document.s3_key
        )
        print(f"✅ Deleted from S3: {document.s3_key}")
    except ClientError as e:
        print(f"❌ S3 delete error: {e}")
        flash(f'Error deleting file from S3: {str(e)}', 'error')
    
    # Delete from database
    db.session.delete(document)
    db.session.commit()
    
    flash('Document deleted successfully.', 'success')
    return redirect(url_for('onboarding.admin_documents'))

# ==================== ADMIN PROFILE MANAGEMENT ====================

@onboarding_bp.route('/admin/profile', methods=['GET', 'POST'])
@login_required
def admin_profile():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    
    employee = Employee.query.filter_by(user_id=current_user.id).first()
    
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        email = request.form.get('email','').strip()
        department = request.form.get('department','').strip()
        
        if not name or not email:
            flash('Name and email are required.', 'error')
            return redirect(url_for('onboarding.admin_profile'))
        
        # Check if email is already taken by another user
        existing_employee = Employee.query.filter(Employee.email == email, Employee.id != employee.id).first()
        if existing_employee:
            flash('Email already exists.', 'error')
            return redirect(url_for('onboarding.admin_profile'))
        
        employee.name = name
        employee.email = email
        employee.department = department
        employee.is_submitted = True
        employee.submitted_at = datetime.utcnow()
        db.session.commit()
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('onboarding.admin_dashboard'))
    
    return render_template('admin_profile.html', employee=employee)

# ==================== DELETE EMPLOYEE ====================

@onboarding_bp.route('/admin/delete_employee/<int:employee_id>')
@login_required
def delete_employee(employee_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    
    employee = Employee.query.get_or_404(employee_id)
    user = User.query.get(employee.user_id)
    
    if user.is_admin:
        flash('Cannot delete admin accounts.', 'error')
        return redirect(url_for('onboarding.admin_dashboard'))
    
    # Soft delete - set employee data to null but keep user account and documents
    employee.name = None
    employee.department = None
    employee.profile_image_url = None
    employee.s3_key = None
    employee.is_submitted = False
    employee.submitted_at = None
    employee.is_active = False  # Mark as inactive
    
    db.session.commit()
    
    flash(f'Employee {employee.email} has been deactivated. Their documents are preserved.', 'success')
    return redirect(url_for('onboarding.admin_dashboard'))

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
        try:
            # Personal Details
            name = request.form.get('fullName','').strip()
            father_name = request.form.get('fatherName','').strip()
            address = request.form.get('address','').strip()
            permanent_address = request.form.get('permanentAddress','').strip()
            blood_group = request.form.get('bloodGroup','').strip()
            mobile = request.form.get('mobile','').strip()
            email = request.form.get('email','').strip()
            emergency_contact_name = request.form.get('emergencyName','').strip()
            emergency_contact_number = request.form.get('emergencyContact','').strip()
            
            # Validate required fields
            required_fields = {
                'name': name,
                'father_name': father_name,
                'address': address,
                'permanent_address': permanent_address,
                'blood_group': blood_group,
                'mobile': mobile,
                'email': email,
                'emergency_contact_name': emergency_contact_name,
                'emergency_contact_number': emergency_contact_number
            }
            
            missing_fields = [field for field, value in required_fields.items() if not value]
            if missing_fields:
                flash('Please fill all required personal details fields.', 'error')
                return redirect(url_for('onboarding.profile_setup'))
            
            # Education Details
            education_data = {
                'ssc': {
                    'school_name': request.form.get('sscSchoolName'),
                    'hall_ticket_no': request.form.get('sscHTNo'),
                    'passout_year': request.form.get('sscPassoutYear'),
                    'percentage': request.form.get('sscPercentage')
                },
                'intermediate': {
                    'college_name': request.form.get('interCollegeName'),
                    'hall_ticket_no': request.form.get('interHTNo'),
                    'passout_year': request.form.get('interPassoutYear'),
                    'percentage': request.form.get('interPercentage')
                },
                'graduation': {
                    'college_name': request.form.get('gradCollegeName'),
                    'passout_year': request.form.get('gradPassoutYear'),
                    'reg_number': request.form.get('gradRegNumber'),
                    'percentage': request.form.get('gradPercentage')
                },
                'post_graduation': {
                    'college_name': request.form.get('postGradCollegeName'),
                    'passout_year': request.form.get('postGradPassoutYear'),
                    'reg_number': request.form.get('postGradRegNumber'),
                    'percentage': request.form.get('postGradPercentage')
                }
            }
            
            # Internship Details
            has_internship = request.form.get('internship') == 'yes'
            internship_data = {
                'has_internship': has_internship,
                'internships': []
            }
            
            if has_internship:
                # Main internship
                internship = {
                    'company_name': request.form.get('internshipCompanyName'),
                    'designation': request.form.get('internshipDesignation'),
                    'poc_name': request.form.get('internshipPOC'),
                    'poc_email': request.form.get('internshipPOCEmail'),
                    'poc_phone': request.form.get('internshipPOCPhone'),
                    'date_of_joining': request.form.get('internshipDoj'),
                    'date_of_relieving': request.form.get('internshipDor')
                }
                internship_data['internships'].append(internship)
            
            # Experience Details
            has_experience = request.form.get('experience') == 'yes'
            experience_data = {
                'has_experience': has_experience,
                'experiences': []
            }
            
            if has_experience:
                experience = {
                    'company_name': request.form.get('experienceCompanyName'),
                    'designation': request.form.get('experienceDesignation'),
                    'poc_name': request.form.get('experiencePOC'),
                    'poc_email': request.form.get('experiencePOCEmail'),
                    'poc_phone': request.form.get('experiencePOCPhone'),
                    'date_of_joining': request.form.get('experienceDoj'),
                    'date_of_relieving': request.form.get('experienceDor')
                }
                experience_data['experiences'].append(experience)
            
            # Other Details
            other_data = {
                'aadhar': {
                    'number': request.form.get('aadharNumber'),
                },
                'pan': {
                    'number': request.form.get('panNumber'),
                },
                'bank': {
                    'bank_name': request.form.get('bankName'),
                    'branch_name': request.form.get('branchName'),
                    'account_number': request.form.get('accountNumber'),
                    'ifsc_code': request.form.get('ifscCode')
                },
                'voter_id': request.form.get('voterid'),
                'driving_license': request.form.get('Licencenumber')
            }
            
            # Update employee record
            employee.name = name
            employee.father_name = father_name
            employee.address = address
            employee.permanent_address = permanent_address
            employee.blood_group = blood_group
            employee.mobile = mobile
            employee.email = email
            employee.emergency_contact_name = emergency_contact_name
            employee.emergency_contact_number = emergency_contact_number
            employee.education_details = json.dumps(education_data)
            employee.internship_details = json.dumps(internship_data)
            employee.experience_details = json.dumps(experience_data)
            employee.other_details = json.dumps(other_data)
            employee.is_submitted = True
            employee.submitted_at = datetime.utcnow()
            
            # Handle file uploads
            files_handled = handle_file_uploads(request, employee)
            
            db.session.commit()
            
            flash('Your profile has been submitted successfully!', 'success')
            return redirect(url_for('onboarding.dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error submitting profile: {str(e)}', 'error')
            return redirect(url_for('onboarding.profile_setup'))
    
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
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from candidate_onboarding.models import User, Employee, Document
from candidate_onboarding import db

onboarding_bp = Blueprint('onboarding', __name__)

@onboarding_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # redirect based on role
        if getattr(current_user, 'is_admin', False):
            return redirect(url_for('onboarding.admin_dashboard'))
        return redirect(url_for('onboarding.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            # FIXED: Redirect based on user role after login
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

# Admin dashboard
@onboarding_bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))
    employees = Employee.query.all()
    return render_template('admin_dashboard.html', employees=employees)

@onboarding_bp.route('/admin/create_employee', methods=['GET', 'POST'])
@login_required
def create_employee():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('onboarding.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()
        email = request.form.get('email','').strip()

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('onboarding.create_employee'))

        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw, is_admin=False)
        db.session.add(new_user)
        db.session.commit()

        new_employee = Employee(user_id=new_user.id, email=email)
        db.session.add(new_employee)
        db.session.commit()

        flash(f'Employee account created for {username}!', 'success')
        return redirect(url_for('onboarding.admin_dashboard'))

    return render_template('create_employee.html')

# Employee dashboard
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

# Profile setup
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
        db.session.commit()
        flash('Your profile has been submitted successfully!', 'success')
        return redirect(url_for('onboarding.dashboard'))
    return render_template('profile_setup.html', employee=employee)

# Reset profile
@onboarding_bp.route('/reset_profile')
@login_required
def reset_profile():
    if current_user.is_admin:
        return redirect(url_for('onboarding.admin_dashboard'))
    
    employee = Employee.query.filter_by(user_id=current_user.id).first()
    if employee:
        employee.name = None
        employee.department = None
        employee.profile_image_url = None
        employee.is_submitted = False
        Document.query.filter_by(employee_id=employee.id).delete()
        db.session.commit()
    flash('Your profile has been reset. You can start over.', 'info')
    return redirect(url_for('onboarding.profile_setup'))
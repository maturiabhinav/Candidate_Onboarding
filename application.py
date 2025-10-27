import os
from flask import Flask
from candidate_onboarding import db, login_manager, mail
from candidate_onboarding.routes import onboarding_bp
from candidate_onboarding.models import User, Employee
from flask_login import LoginManager
from werkzeug.security import generate_password_hash
from urllib.parse import urlparse
import sqlalchemy as sa
from flask import redirect, url_for

# Initialize Flask app
app = Flask(__name__)

# --- Configuration ---
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret-key")

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Detect DATABASE_URL (PostgreSQL on Railway)
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL or "sqlite:///local.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- Custom Jinja2 Filters ---
def format_india_time(value):
    """Custom filter to display datetime in India timezone (IST)"""
    if value is None:
        return ""
    
    # India is UTC+5:30
    india_offset = timedelta(hours=5, minutes=30)
    
    # If datetime is naive (no timezone), assume UTC
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    
    # Convert to India time (UTC+5:30)
    india_time = value + india_offset
    
    # Format as desired: "YYYY-MM-DD HH:MM IST"
    return india_time.strftime('%Y-%m-%d %H:%M IST')

# Register the custom filter with Jinja2
app.jinja_env.filters['india_time'] = format_india_time

# Register blueprint
app.register_blueprint(onboarding_bp)

# Initialize extensions
login_manager.init_app(app)
login_manager.login_view = "onboarding.login"
mail.init_app(app)
db.init_app(app)

# --- Smart Database Setup ---
with app.app_context():
    try:
        # Try to query the user table - if it fails, create tables
        User.query.first()
        print("ℹ️ Database tables already exist")
        
        # Check if is_active column exists in employee table
        inspector = sa.inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('employee')]
        
        if 'is_active' not in columns:
            print("🔄 Adding is_active column to employee table...")
            try:
                # Correct way to execute raw SQL with SQLAlchemy 2.0+
                with db.engine.connect() as conn:
                    conn.execute(sa.text('ALTER TABLE employee ADD COLUMN is_active BOOLEAN DEFAULT TRUE'))
                    conn.commit()
                print("✅ is_active column added successfully")
                
                # Update existing employees to be active
                with db.engine.connect() as conn:
                    conn.execute(sa.text('UPDATE employee SET is_active = TRUE WHERE is_active IS NULL'))
                    conn.commit()
                print("✅ Existing employees marked as active")
                
            except Exception as e:
                print(f"❌ Error adding is_active column: {e}")
                # If column addition fails, recreate tables
                print("🔄 Column addition failed, recreating tables...")
                db.drop_all()
                db.create_all()
                print("✅ Database tables recreated")
        
    except Exception as e:
        print(f"🔄 Creating database tables... (Error: {e})")
        db.drop_all()
        db.create_all()
        print("✅ Database tables created")
    
    # Create admin user only if it doesn't exist
    admin_user = User.query.filter_by(username="admin").first()
    if not admin_user:
        default_admin = User(
            username="admin",
            password=generate_password_hash("Admin@123"),
            is_admin=True
        )
        db.session.add(default_admin)
        db.session.commit()
        
        # Create employee record for admin
        admin_employee = Employee(
            user_id=default_admin.id, 
            email="admin@company.com",
            name="Administrator",
            is_submitted=True,
            is_active=True
        )
        db.session.add(admin_employee)
        db.session.commit()
        print("✅ Default admin account created: admin / Admin@123")
    else:
        print("ℹ️ Admin account already exists")

# --- User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Root Route ---
@app.route("/")
def home():
    return redirect(url_for('login'))

# Your login route
@app.route("/login")
def login():
    return "<h3>Login Page</h3>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
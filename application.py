import os
from flask import Flask
from candidate_onboarding import db, login_manager, mail
from candidate_onboarding.routes import onboarding_bp
from candidate_onboarding.models import User
from flask_login import LoginManager
from werkzeug.security import generate_password_hash
from urllib.parse import urlparse

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

# Register blueprint
app.register_blueprint(onboarding_bp)

# Initialize extensions
login_manager.init_app(app)
login_manager.login_view = "onboarding.login"
mail.init_app(app)
db.init_app(app)

# --- Auto-create DB and default admin ---
with app.app_context():
    # Drop all tables and recreate them
    db.drop_all()
    db.create_all()
    
    admin_user = User.query.filter_by(username="admin").first()
    if not admin_user:
        default_admin = User(
            username="admin",
            password=generate_password_hash("Admin@123"),
            is_admin=True,
            is_verified=True  # Admin doesn't need verification
        )
        db.session.add(default_admin)
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
    return "<h3>Server is running! Go to /login</h3>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
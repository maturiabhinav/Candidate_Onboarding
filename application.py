import os
from flask import Flask
from candidate_onboarding import db
from candidate_onboarding.routes import onboarding_bp
from candidate_onboarding.models import User
from flask_login import LoginManager
from werkzeug.security import generate_password_hash
from urllib.parse import urlparse

# Initialize Flask app
app = Flask(__name__)

# --- Configuration ---
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret-key")

# Detect DATABASE_URL (PostgreSQL on Railway)
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL or "sqlite:///local.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Register blueprint
app.register_blueprint(onboarding_bp)

# Initialize extensions
login_manager = LoginManager(app)
login_manager.login_view = "onboarding.login"
db.init_app(app)

# --- Auto-create DB and default admin ---
with app.app_context():
    db.create_all()
    admin_user = User.query.filter_by(username="admin").first()
    if not admin_user:
        default_admin = User(
            username="admin",
            password=generate_password_hash("Admin@123"),
            is_admin=True
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

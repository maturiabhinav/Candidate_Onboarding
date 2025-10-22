import os
from flask import Flask, render_template
from flask_login import LoginManager
from candidate_onboarding import db
from candidate_onboarding.routes import onboarding_bp
from candidate_onboarding.models import User
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

# Database (Railway will provide DATABASE_URL env var)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///onboarding.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Login manager setup
login_manager = LoginManager(app)
login_manager.login_view = "onboarding.login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Register Blueprints
app.register_blueprint(onboarding_bp)

# Create tables and default admin if DB is reachable
with app.app_context():
    try:
        db.create_all()
        # Create default admin if not exists
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", password=generate_password_hash("Admin@123"))
            db.session.add(admin)
            db.session.commit()
            print("✅ Default admin account created: admin / Admin@123")
        else:
            print("✅ Admin user already exists")
    except Exception as e:
        print("⚠️  DB initialization skipped or failed:", e)

@app.route('/')
def home():
    return render_template('login.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

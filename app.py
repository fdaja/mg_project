from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-default-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

# SQLAlchemy Configuration
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set.")

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    confirmation_code = db.Column(db.String(6), nullable=True)

class Gadget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    gadget_name = db.Column(db.String(100), nullable=False)
    serial_number = db.Column(db.String(100), unique=True, nullable=False)
    note = db.Column(db.Text, nullable=True)
    report_type_id = db.Column(db.Integer, nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

# Utility Functions
def send_confirmation_email(email, confirmation_code):
    try:
        msg = Message(
            'Your Registration Confirmation Code',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f"Your confirmation code is: {confirmation_code}"
        mail.send(msg)
        logging.info(f"Confirmation email sent to {email}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        raise

# Routes
@app.route('/')
def index():
    return jsonify({'message': 'Welcome to the MG Project API!'})

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    try:
        password = data.get('password')
        if not password:
            return jsonify({'error': 'Password is required'}), 400

        hashed_password = generate_password_hash(password)
        confirmation_code = str(random.randint(100000, 999999))

        user = User(
            name=data['name'],
            username=data['username'],
            email=data['email'],
            password_hash=hashed_password,
            confirmation_code=confirmation_code
        )
        db.session.add(user)
        db.session.commit()

        send_confirmation_email(data['email'], confirmation_code)

        return jsonify({'id': user.id, 'message': 'User registered successfully! Please check your email for the confirmation code.'}), 201
    except Exception as e:
        logging.error(f"Error in register_user: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/confirm', methods=['POST'])
def confirm_user():
    data = request.json
    email = data.get('email')
    code = data.get('confirmation_code')
    try:
        user = User.query.filter_by(email=email, confirmation_code=code, is_verified=False).first()
        if not user:
            return jsonify({'error': 'Invalid email or confirmation code.'}), 400

        user.is_verified = True
        user.confirmation_code = None
        db.session.commit()

        return jsonify({'message': 'User verified successfully!'}), 200
    except Exception as e:
        logging.error(f"Error in confirm_user: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    try:
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid username or password'}), 401

        access_token = create_access_token(identity=str(user.id))
        return jsonify({'access_token': access_token, 'user_id': user.id}), 200
    except Exception as e:
        logging.error(f"Error in login: {e}")
        return jsonify({'error': str(e)}), 500

# Additional routes can be added following the same pattern

if __name__ == '__main__':
    logging.info("Registered Routes:")
    for rule in app.url_map.iter_rules():
        logging.info(rule)

    app.run(debug=True)

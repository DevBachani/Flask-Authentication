from flask import Flask, request, jsonify, session
from flask_mongoengine import MongoEngine
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

app = Flask(__name__)

# Configuration
app.config['MONGODB_SETTINGS'] = {
    'db': 'dbmongocrud',
    'host': 'localhost',
    'port': 27017
}
app.secret_key = 'your_secret_key'  # Secret key for session management

db = MongoEngine()
db.init_app(app)

# User Model
class User(db.Document):
    name = db.StringField(required=True)
    email = db.StringField(required=True, unique=True)
    password = db.StringField(required=True)

    def to_json(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "email": self.email
        }

# Root Endpoint
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        "status": "Login API is online"
    }), 200

# Register User
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'error': 'Name, email, and password are required'}), 400

    # Check if email already exists
    if User.objects(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400

    # Hash the password
    hashed_password = generate_password_hash(password)
    new_user = User(name=name, email=email, password=hashed_password)
    new_user.save()

    return jsonify({'message': 'User registered successfully', 'user': new_user.to_json()}), 201

# Login User
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = User.objects(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid email or password'}), 401

    # Generate a session ID
    session_id = str(uuid.uuid4())
    session['session_id'] = session_id  # Store session ID in Flask session
    session['user_id'] = str(user.id)   # Store user ID in session for reference

    return jsonify({
        'message': 'Login successful',
        'user': user.to_json(),
        'session_id': session_id
    }), 200

# Check Session (Optional Route for Testing)
@app.route('/session', methods=['GET'])
def check_session():
    if 'session_id' in session:
        return jsonify({
            'message': 'Session active',
            'session_id': session['session_id'],
            'user_id': session.get('user_id')
        }), 200
    return jsonify({'error': 'No active session'}), 401

if __name__ == "__main__":
    app.run(debug=True)

from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)

# Configuration for the database and secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize database and enable CORS
db = SQLAlchemy(app)
CORS(app)  

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Register route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if username or password is missing
    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400
    
    # Check if username already exists
    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists!"}), 400
    
    # Hash the password and create a new user
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"}), 201

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if username or password is missing
    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400

    # Find the user by username and check the password
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid credentials!"}), 401

    # Store user ID in session
    session['user_id'] = user.id
    return jsonify({"message": "Login successful!"}), 200

# Logout route
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({"message": "Logged out successfully!"}), 200

# Route to check if a user is logged in
@app.route('/check_session', methods=['GET'])
def check_session():
    if 'user_id' in session:
        return jsonify({"logged_in": True, "user_id": session['user_id']}), 200
    return jsonify({"logged_in": False}), 200

# Get user information after login
@app.route('/user_info', methods=['GET'])
def user_info():
    if 'user_id' not in session:
        return jsonify({"message": "Not logged in"}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    return jsonify({"username": user.username}), 200

if __name__ == '__main__':
    # Ensure the application context is used when creating the database tables
    with app.app_context():
        db.create_all()  
    app.run(debug=True)

# backend/app.py
import os
from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS # Import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
import uuid # For generating unique file IDs
from werkzeug.security import generate_password_hash, check_password_hash # For basic password hashing

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__, static_folder='../frontend', static_url_path='/')
CORS(app) # Enable CORS for all routes

# MongoDB Connection
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient('mongodb://localhost:27017/')
db = client['dissertation_db'] # Your database name
users_collection = db['users'] # Collection for storing user data
keys_collection = db['wrapped_keys'] # Collection for storing wrapped keys

# Ensure unique index on username for users collection
users_collection.create_index("username", unique=True)

@app.route('/')
def serve_index():
    """Serve the main HTML file."""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve other static files (CSS, JS)."""
    return send_from_directory(app.static_folder, path)

@app.route('/api/register', methods=['POST'])
def register_user():
    """API endpoint for user registration."""
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    if users_collection.find_one({'username': username}):
        return jsonify({'error': 'Username already exists'}), 409

    hashed_password = generate_password_hash(password)
    user_id = str(uuid.uuid4()) # Generate a unique user ID

    user_data = {
        'user_id': user_id,
        'username': username,
        'password_hash': hashed_password
    }
    users_collection.insert_one(user_data)

    return jsonify({'message': 'User registered successfully', 'user_id': user_id}), 201

@app.route('/api/login', methods=['POST'])
def login_user():
    """API endpoint for user login."""
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    user = users_collection.find_one({'username': username})

    if user and check_password_hash(user['password_hash'], password):
        return jsonify({'message': 'Login successful', 'user_id': user['user_id']}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/keys', methods=['POST'])
def save_wrapped_key():
    """API endpoint to save a wrapped key."""
    data = request.json
    required_fields = ['wrappedKey', 'iv', 'salt', 'keyWrappingIv', 'originalFileName', 'fileId', 'userId']
    
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required data fields'}), 400
    
    # Store the wrapped key and relevant metadata
    # In a real app, you'd add more validation and proper user session checks
    keys_collection.insert_one(data)
    return jsonify({'message': 'Key saved successfully', 'id': str(data['_id'])}), 201

@app.route('/api/keys/<string:user_id>/<string:file_id>', methods=['GET'])
def get_wrapped_key(user_id, file_id):
    """API endpoint to retrieve a wrapped key by user ID and file ID."""
    key_data = keys_collection.find_one({'userId': user_id, 'fileId': file_id})
    if key_data:
        # Convert ObjectId to string for JSON serialization
        key_data['_id'] = str(key_data['_id'])
        return jsonify(key_data), 200
    return jsonify({'error': 'Key not found'}), 404

@app.route('/api/keys/<string:user_id>', methods=['GET'])
def list_user_keys(user_id):
    """API endpoint to list all wrapped keys for a given user ID."""
    user_keys = list(keys_collection.find({'userId': user_id}, {'_id': 0, 'fileId': 1, 'originalFileName': 1}))
    return jsonify(user_keys), 200

@app.route('/api/keys/<string:user_id>/<string:file_id>', methods=['DELETE'])
def delete_wrapped_key(user_id, file_id):
    """API endpoint to delete a wrapped key."""
    result = keys_collection.delete_one({'userId': user_id, 'fileId': file_id})
    if result.deleted_count > 0:
        return jsonify({'message': 'Key deleted successfully'}), 200
    return jsonify({'error': 'Key not found or not authorized'}), 404

if __name__ == '__main__':
    # For development, ensure you have python-dotenv installed and a .env file
    # For production, consider using a WSGI server like Gunicorn
    app.run(debug=True, port=5000)

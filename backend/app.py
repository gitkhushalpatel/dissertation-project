import os
from flask import Flask, send_from_directory, request, jsonify
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__, static_folder='../frontend', static_url_path='/')

# MongoDB Connection
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient('mongodb://localhost:27017/')
db = client['dissertationproject_db'] # Your database name
keys_collection = db['wrapped_keys'] # Collection for storing wrapped keys

@app.route('/')
def serve_index():
    """Serve the main HTML file."""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve other static files (CSS, JS)."""
    return send_from_directory(app.static_folder, path)

@app.route('/api/keys', methods=['POST'])
def save_wrapped_key():
    """API endpoint to save a wrapped key."""
    data = request.json
    if not data or 'wrappedKey' not in data or 'fileId' not in data or 'userId' not in data:
        return jsonify({'error': 'Missing data'}), 400
    
    # Store the wrapped key and relevant metadata
    # In a real app, you'd add more validation and potentially user authentication
    keys_collection.insert_one(data)
    return jsonify({'message': 'Key saved successfully', 'id': str(data['_id'])}), 201

@app.route('/api/keys/<string:file_id>', methods=['GET'])
def get_wrapped_key(file_id):
    """API endpoint to retrieve a wrapped key by file ID."""
    key_data = keys_collection.find_one({'fileId': file_id})
    if key_data:
        # Convert ObjectId to string for JSON serialization
        key_data['_id'] = str(key_data['_id'])
        return jsonify(key_data), 200
    return jsonify({'error': 'Key not found'}), 404

if __name__ == '__main__':
    app.run(debug=True, port=5000) # Run on port 5000, debug=True for development
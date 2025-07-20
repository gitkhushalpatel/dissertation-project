# backend/app.py
import os
import sqlite3
from flask import Flask, send_from_directory, request, jsonify, g, send_file
from flask_cors import CORS
from dotenv import load_dotenv
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import base64
from io import BytesIO

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='../frontend', static_url_path='/')
CORS(app)

# Database configuration
DATABASE = os.path.join(os.path.dirname(__file__), 'dissertation.db')

def get_db():
    """Get database connection."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # This allows us to access columns by name
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    """Close database connection at the end of each request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the database with the correct schema, including encrypted_data."""
    with app.app_context():
        db = get_db()
        # Updated schema to include the encrypted_data column
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS wrapped_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                wrapped_key TEXT NOT NULL,
                iv TEXT NOT NULL,
                salt TEXT NOT NULL,
                key_wrapping_iv TEXT NOT NULL,
                original_file_name TEXT NOT NULL,
                encrypted_data BLOB NOT NULL, -- Stores the actual encrypted file content
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, file_id),
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            );

            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id);
            CREATE INDEX IF NOT EXISTS idx_wrapped_keys_user_id ON wrapped_keys(user_id);
            CREATE INDEX IF NOT EXISTS idx_wrapped_keys_file_id ON wrapped_keys(file_id);
        ''')
        db.commit()
        logger.info("Database initialized successfully with updated schema.")

# Initialize database when app starts
with app.app_context():
    init_db()

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
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
        
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
        
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters long'}), 400
        
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters long'}), 400

    db = get_db()
    
    existing_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 409

    hashed_password = generate_password_hash(password)
    user_id = str(uuid.uuid4())

    try:
        db.execute(
            'INSERT INTO users (user_id, username, password_hash) VALUES (?, ?, ?)',
            (user_id, username, hashed_password)
        )
        db.commit()
        logger.info(f"New user registered: {username}")
        return jsonify({'message': 'User registered successfully', 'user_id': user_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def login_user():
    """API endpoint for user login."""
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
        
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    db = get_db()
    user = db.execute(
        'SELECT user_id, password_hash FROM users WHERE username = ?', (username,)
    ).fetchone()

    if user and check_password_hash(user['password_hash'], password):
        logger.info(f"User logged in: {username}")
        return jsonify({'message': 'Login successful', 'user_id': user['user_id']}), 200
    else:
        logger.warning(f"Failed login attempt for username: {username}")
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/keys', methods=['POST'])
def save_wrapped_key():
    """
    API endpoint to save a wrapped key and the encrypted file data.
    Expects a multipart/form-data request.
    """
    logger.info(f"Received POST to /api/keys")
    logger.info(f"Request Content-Type: {request.headers.get('Content-Type')}")

    # Log all form data received
    logger.info(f"Form data received: {request.form}")
    for key, value in request.form.items():
        logger.info(f"  Form field - {key}: {value}")

    # Log all files received
    logger.info(f"Files received: {request.files}")
    if not request.files:
        logger.warning("No files were found in the request.files object.")
        return jsonify({'error': 'No files were found in the request'}), 400 # More generic error here

    if 'encryptedFile' not in request.files:
        logger.error("The 'encryptedFile' part is specifically missing from request.files.")
        return jsonify({'error': 'Missing encrypted file part. Backend could not find "encryptedFile" in request.files.'}), 400
    
    encrypted_file = request.files['encryptedFile']
    
    if encrypted_file.filename == '':
        logger.error("Encrypted file was submitted but its filename is empty.")
        return jsonify({'error': 'No selected file for encryption'}), 400

    encrypted_data = encrypted_file.read()

    if not encrypted_data:
        logger.error("Encrypted file content is empty after reading.")
        return jsonify({'error': 'Encrypted file is empty after read'}), 400

    # Original metadata extraction (keep this)
    data = request.form
    required_fields = ['wrappedKey', 'iv', 'salt', 'keyWrappingIv', 'originalFileName', 'fileId', 'userId']
    if not all(field in data for field in required_fields):
        missing_fields = [field for field in required_fields if field not in data]
        logger.error(f"Missing required metadata fields: {missing_fields}")
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    db = get_db()
    
    user = db.execute('SELECT id FROM users WHERE user_id = ?', (data['userId'],)).fetchone()
    if not user:
        logger.error(f"Invalid user ID received: {data['userId']}")
        return jsonify({'error': 'Invalid user'}), 401
    
    try:
        db.execute('''
            INSERT INTO wrapped_keys 
            (user_id, file_id, wrapped_key, iv, salt, key_wrapping_iv, original_file_name, encrypted_data) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['userId'],
            data['fileId'],
            data['wrappedKey'],
            data['iv'],
            data['salt'],
            data['keyWrappingIv'],
            data['originalFileName'],
            encrypted_data 
        ))
        db.commit()
        
        key_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        logger.info(f"Key and file saved for user {data['userId']}: {data['originalFileName']}")
        return jsonify({'message': 'Key and file saved successfully', 'id': key_id}), 201
    except sqlite3.IntegrityError:
        logger.error(f"IntegrityError: Key with file ID {data['fileId']} already exists for user {data['userId']}")
        return jsonify({'error': 'Key with this file ID already exists for this user'}), 409
    except Exception as e:
        logger.error(f"Error saving key and file: {e}", exc_info=True) # exc_info=True prints traceback
        return jsonify({'error': 'Failed to save key and file'}), 500
    
@app.route('/api/keys/<string:user_id>/<string:file_id>', methods=['GET'])
def get_wrapped_key(user_id, file_id):
    """
    API endpoint to retrieve a wrapped key and OTHER metadata by user ID and file ID.
    This endpoint NO LONGER returns the encrypted_data.
    """
    db = get_db()
    key_data = db.execute('''
        SELECT id, user_id, file_id, wrapped_key, iv, salt, key_wrapping_iv, original_file_name, created_at
        FROM wrapped_keys 
        WHERE user_id = ? AND file_id = ?
    ''', (user_id, file_id)).fetchone()
    
    if key_data:
        key_dict = {
            'id': key_data['id'],
            'userId': key_data['user_id'],
            'fileId': key_data['file_id'],
            'wrappedKey': key_data['wrapped_key'],
            'iv': key_data['iv'],
            'salt': key_data['salt'],
            'keyWrappingIv': key_data['key_wrapping_iv'],
            'originalFileName': key_data['original_file_name'],
            'createdAt': key_data['created_at'],
        }
        return jsonify(key_dict), 200
    return jsonify({'error': 'Key metadata not found for this file ID and user.'}), 404

@app.route('/api/files/<string:user_id>/<string:file_id>', methods=['GET'])
def get_encrypted_file_content(user_id, file_id):
    """
    NEW API endpoint to retrieve the raw encrypted file content (BLOB) by user ID and file ID.
    """
    db = get_db()
    file_data = db.execute('''
        SELECT encrypted_data, original_file_name
        FROM wrapped_keys
        WHERE user_id = ? AND file_id = ?
    ''', (user_id, file_id)).fetchone()

    if file_data:
        # Use BytesIO to create a file-like object from the BLOB data
        # send_file requires a file-like object or a path
        return send_file(
            BytesIO(file_data['encrypted_data']),
            mimetype='application/octet-stream', # Generic binary type
            as_attachment=True,
            download_name=f"encrypted_{file_data['original_file_name']}.enc" # Suggest a download name
        )
    return jsonify({'error': 'Encrypted file content not found or not authorized.'}), 404


@app.route('/api/keys/<string:user_id>', methods=['GET'])
def list_user_keys(user_id):
    """API endpoint to list all files (keys) for a given user ID."""
    db = get_db()
    user_keys = db.execute('''
        SELECT file_id, original_file_name, created_at
        FROM wrapped_keys 
        WHERE user_id = ?
        ORDER BY created_at DESC
    ''', (user_id,)).fetchall()
    
    keys_list = [
        {
            'fileId': row['file_id'],
            'originalFileName': row['original_file_name'],
            'createdAt': row['created_at']
        }
        for row in user_keys
    ]
    
    return jsonify(keys_list), 200

@app.route('/api/keys/<string:user_id>/<string:file_id>', methods=['DELETE'])
def delete_wrapped_key(user_id, file_id):
    """API endpoint to delete a wrapped key and its associated file data."""
    db = get_db()
    cursor = db.execute('''
        DELETE FROM wrapped_keys 
        WHERE user_id = ? AND file_id = ?
    ''', (user_id, file_id))
    db.commit()
    
    if cursor.rowcount > 0:
        logger.info(f"Key and file deleted for user {user_id}, file {file_id}")
        return jsonify({'message': 'Key and file deleted successfully'}), 200
    return jsonify({'error': 'Key not found or not authorized'}), 404

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'message': 'SecureVault API is running'}), 200

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)

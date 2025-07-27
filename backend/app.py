# backend/app.py
import os
import sqlite3
import json
import io
from flask import Flask, send_from_directory, request, jsonify, g, send_file
from flask_cors import CORS
from dotenv import load_dotenv
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import base64
from io import BytesIO

# Google Drive imports
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='../frontend', static_url_path='/')
CORS(app)

# Database configuration
DATABASE = os.path.join(os.path.dirname(__file__), 'dissertation.db')

# Google Drive configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:5000/api/auth/google/callback')

# Scopes required for Google Drive
SCOPES = ['https://www.googleapis.com/auth/drive.file']

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
    """Initialize the database with the correct schema, including Google Drive support."""
    with app.app_context():
        db = get_db()
        
        # Create tables if they don't exist
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
                encrypted_data BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, file_id),
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            );
        ''')
        
        # Add new columns if they don't exist (migration)
        try:
            # Check if google_drive_token column exists in users table
            cursor = db.execute("PRAGMA table_info(users)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'google_drive_token' not in columns:
                db.execute('ALTER TABLE users ADD COLUMN google_drive_token TEXT')
                logger.info("Added google_drive_token column to users table")
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not add google_drive_token column: {e}")
        
        try:
            # Check if new columns exist in wrapped_keys table
            cursor = db.execute("PRAGMA table_info(wrapped_keys)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'google_drive_file_id' not in columns:
                db.execute('ALTER TABLE wrapped_keys ADD COLUMN google_drive_file_id TEXT')
                logger.info("Added google_drive_file_id column to wrapped_keys table")
            
            if 'storage_location' not in columns:
                db.execute('ALTER TABLE wrapped_keys ADD COLUMN storage_location TEXT DEFAULT "local"')
                logger.info("Added storage_location column to wrapped_keys table")
                
                # Update existing records to have 'local' storage location
                db.execute('UPDATE wrapped_keys SET storage_location = "local" WHERE storage_location IS NULL')
                logger.info("Updated existing records with 'local' storage location")
                
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not add columns to wrapped_keys table: {e}")
        
        # Also need to make encrypted_data nullable for Google Drive files
        try:
            # Check if we need to recreate the table to make encrypted_data nullable
            cursor = db.execute("PRAGMA table_info(wrapped_keys)")
            table_info = cursor.fetchall()
            encrypted_data_info = next((col for col in table_info if col[1] == 'encrypted_data'), None)
            
            if encrypted_data_info and encrypted_data_info[3] == 1:  # NOT NULL constraint exists
                logger.info("Recreating wrapped_keys table to make encrypted_data nullable...")
                
                # Create backup table
                db.execute('''
                    CREATE TABLE wrapped_keys_backup AS 
                    SELECT * FROM wrapped_keys
                ''')
                
                # Drop original table
                db.execute('DROP TABLE wrapped_keys')
                
                # Recreate table with correct schema
                db.execute('''
                    CREATE TABLE wrapped_keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id TEXT NOT NULL,
                        file_id TEXT NOT NULL,
                        wrapped_key TEXT NOT NULL,
                        iv TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        key_wrapping_iv TEXT NOT NULL,
                        original_file_name TEXT NOT NULL,
                        encrypted_data BLOB,
                        google_drive_file_id TEXT,
                        storage_location TEXT DEFAULT 'local',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(user_id, file_id),
                        FOREIGN KEY (user_id) REFERENCES users (user_id)
                    )
                ''')
                
                # Restore data
                db.execute('''
                    INSERT INTO wrapped_keys 
                    SELECT * FROM wrapped_keys_backup
                ''')
                
                # Drop backup table
                db.execute('DROP TABLE wrapped_keys_backup')
                
                logger.info("Successfully recreated wrapped_keys table")
                
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not modify encrypted_data column: {e}")
        
        # Create indexes
        try:
            db.executescript('''
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id);
                CREATE INDEX IF NOT EXISTS idx_wrapped_keys_user_id ON wrapped_keys(user_id);
                CREATE INDEX IF NOT EXISTS idx_wrapped_keys_file_id ON wrapped_keys(file_id);
                CREATE INDEX IF NOT EXISTS idx_wrapped_keys_storage ON wrapped_keys(storage_location);
            ''')
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not create some indexes: {e}")
        
        db.commit()
        logger.info("Database initialized/migrated successfully with Google Drive support.")

# Google Drive API helper functions
def get_drive_service(user_id):
    """Get Google Drive service for a user."""
    db = get_db()
    user = db.execute('SELECT google_drive_token FROM users WHERE user_id = ?', (user_id,)).fetchone()
    
    if not user or not user['google_drive_token']:
        return None
    
    try:
        creds_data = json.loads(user['google_drive_token'])
        credentials = Credentials.from_authorized_user_info(creds_data, SCOPES)
        
        # Refresh token if expired
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            # Update stored credentials
            db.execute(
                'UPDATE users SET google_drive_token = ? WHERE user_id = ?',
                (credentials.to_json(), user_id)
            )
            db.commit()
        
        return build('drive', 'v3', credentials=credentials)
    except Exception as e:
        logger.error(f"Error creating Drive service for user {user_id}: {e}")
        return None

def upload_to_drive(service, file_data, filename, folder_name="SecureVault"):
    """Upload file to Google Drive."""
    try:
        # Create or get SecureVault folder
        folder_id = get_or_create_folder(service, folder_name)
        
        file_metadata = {
            'name': filename,
            'parents': [folder_id] if folder_id else []
        }
        
        media = MediaIoBaseUpload(
            io.BytesIO(file_data),
            mimetype='application/octet-stream',
            resumable=True
        )
        
        file = service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()
        
        return file.get('id')
    except Exception as e:
        logger.error(f"Error uploading to Drive: {e}")
        raise

def download_from_drive(service, file_id):
    """Download file from Google Drive."""
    try:
        request = service.files().get_media(fileId=file_id)
        file_io = io.BytesIO()
        downloader = MediaIoBaseDownload(file_io, request)
        
        done = False
        while done is False:
            status, done = downloader.next_chunk()
        
        return file_io.getvalue()
    except Exception as e:
        logger.error(f"Error downloading from Drive: {e}")
        raise

def get_or_create_folder(service, folder_name):
    """Get existing SecureVault folder or create new one."""
    try:
        # Search for existing folder
        results = service.files().list(
            q=f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder'",
            fields="files(id, name)"
        ).execute()
        
        folders = results.get('files', [])
        if folders:
            return folders[0]['id']
        
        # Create new folder
        folder_metadata = {
            'name': folder_name,
            'mimeType': 'application/vnd.google-apps.folder'
        }
        
        folder = service.files().create(body=folder_metadata, fields='id').execute()
        return folder.get('id')
    except Exception as e:
        logger.error(f"Error managing Drive folder: {e}")
        return None

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
        return jsonify({'error': 'No files were found in the request'}), 400

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
            (user_id, file_id, wrapped_key, iv, salt, key_wrapping_iv, original_file_name, encrypted_data, storage_location) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['userId'],
            data['fileId'],
            data['wrappedKey'],
            data['iv'],
            data['salt'],
            data['keyWrappingIv'],
            data['originalFileName'],
            encrypted_data,
            'local'
        ))
        db.commit()
        
        key_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        logger.info(f"Key and file saved for user {data['userId']}: {data['originalFileName']}")
        return jsonify({'message': 'Key and file saved successfully', 'id': key_id}), 201
    except sqlite3.IntegrityError:
        logger.error(f"IntegrityError: Key with file ID {data['fileId']} already exists for user {data['userId']}")
        return jsonify({'error': 'Key with this file ID already exists for this user'}), 409
    except Exception as e:
        logger.error(f"Error saving key and file: {e}", exc_info=True)
        return jsonify({'error': 'Failed to save key and file'}), 500

@app.route('/api/keys/<string:user_id>/<string:file_id>', methods=['GET'])
def get_wrapped_key(user_id, file_id):
    """
    API endpoint to retrieve a wrapped key and OTHER metadata by user ID and file ID.
    This endpoint NO LONGER returns the encrypted_data.
    """
    db = get_db()
    key_data = db.execute('''
        SELECT id, user_id, file_id, wrapped_key, iv, salt, key_wrapping_iv, original_file_name, 
               storage_location, google_drive_file_id, created_at
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
            'storageLocation': key_data['storage_location'],
            'googleDriveFileId': key_data['google_drive_file_id'],
            'createdAt': key_data['created_at'],
        }
        return jsonify(key_dict), 200
    return jsonify({'error': 'Key metadata not found for this file ID and user.'}), 404

@app.route('/api/files/<string:user_id>/<string:file_id>', methods=['GET'])
def get_encrypted_file_content(user_id, file_id):
    """
    API endpoint to retrieve the raw encrypted file content (BLOB) by user ID and file ID.
    """
    db = get_db()
    file_data = db.execute('''
        SELECT encrypted_data, original_file_name
        FROM wrapped_keys
        WHERE user_id = ? AND file_id = ? AND storage_location = 'local'
    ''', (user_id, file_id)).fetchone()

    if file_data:
        return send_file(
            BytesIO(file_data['encrypted_data']),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f"encrypted_{file_data['original_file_name']}.enc"
        )
    return jsonify({'error': 'Encrypted file content not found or not authorized.'}), 404

@app.route('/api/keys/<string:user_id>', methods=['GET'])
def list_user_keys(user_id):
    """API endpoint to list all files (keys) for a given user ID."""
    db = get_db()
    user_keys = db.execute('''
        SELECT file_id, original_file_name, storage_location, created_at
        FROM wrapped_keys 
        WHERE user_id = ?
        ORDER BY created_at DESC
    ''', (user_id,)).fetchall()
    
    keys_list = [
        {
            'fileId': row['file_id'],
            'originalFileName': row['original_file_name'],
            'storageLocation': row['storage_location'],
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

# Google Drive API endpoints
@app.route('/api/auth/google', methods=['GET'])
def google_auth():
    """Initiate Google OAuth flow."""
    try:
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
            return jsonify({'error': 'Google Drive integration not configured'}), 500
            
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [GOOGLE_REDIRECT_URI]
                }
            },
            scopes=SCOPES
        )
        flow.redirect_uri = GOOGLE_REDIRECT_URI
        
        auth_url, _ = flow.authorization_url(prompt='consent')
        return jsonify({'auth_url': auth_url}), 200
    except Exception as e:
        logger.error(f"Error initiating Google auth: {e}")
        return jsonify({'error': 'Failed to initiate Google authentication'}), 500

@app.route('/api/auth/google/callback', methods=['GET'])
def google_callback():
    """Handle Google OAuth callback."""
    try:
        code = request.args.get('code')
        if not code:
            return jsonify({'error': 'Authorization code not provided'}), 400
        
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [GOOGLE_REDIRECT_URI]
                }
            },
            scopes=SCOPES
        )
        flow.redirect_uri = GOOGLE_REDIRECT_URI
        flow.fetch_token(code=code)
        
        credentials = flow.credentials
        return f"""
        <html>
        <body>
        <h1>Authentication Successful!</h1>
        <p>You can close this window now.</p>
        <script>
            window.opener.postMessage({{
                credentials: {credentials.to_json()}
            }}, window.location.origin);
            window.close();
        </script>
        </body>
        </html>
        """
    except Exception as e:
        logger.error(f"Error in Google callback: {e}")
        return f"<html><body><h1>Error: {str(e)}</h1></body></html>", 500

@app.route('/api/auth/google/store', methods=['POST'])
def store_google_credentials():
    """Store Google Drive credentials for user."""
    data = request.json
    user_id = data.get('user_id')
    credentials_json = data.get('credentials')
    
    if not user_id or not credentials_json:
        return jsonify({'error': 'Missing user_id or credentials'}), 400
    
    try:
        db = get_db()
        db.execute(
            'UPDATE users SET google_drive_token = ? WHERE user_id = ?',
            (credentials_json, user_id)
        )
        db.commit()
        return jsonify({'message': 'Google Drive credentials stored successfully'}), 200
    except Exception as e:
        logger.error(f"Error storing Google credentials: {e}")
        return jsonify({'error': 'Failed to store credentials'}), 500

@app.route('/api/drive/upload', methods=['POST'])
def upload_to_google_drive():
    """Upload encrypted file to Google Drive."""
    try:
        data = request.form
        user_id = data.get('userId')
        
        if not user_id:
            return jsonify({'error': 'User ID required'}), 400
        
        service = get_drive_service(user_id)
        if not service:
            return jsonify({'error': 'Google Drive not connected'}), 401
        
        if 'encryptedFile' not in request.files:
            return jsonify({'error': 'No encrypted file provided'}), 400
        
        encrypted_file = request.files['encryptedFile']
        encrypted_data = encrypted_file.read()
        
        drive_filename = f"SecureVault_{data.get('originalFileName', 'encrypted_file')}.enc"
        drive_file_id = upload_to_drive(service, encrypted_data, drive_filename)
        
        db = get_db()
        db.execute('''
            INSERT INTO wrapped_keys 
            (user_id, file_id, wrapped_key, iv, salt, key_wrapping_iv, original_file_name, 
             google_drive_file_id, storage_location) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id,
            data.get('fileId'),
            data.get('wrappedKey'),
            data.get('iv'),
            data.get('salt'),
            data.get('keyWrappingIv'),
            data.get('originalFileName'),
            drive_file_id,
            'google_drive'
        ))
        db.commit()
        
        return jsonify({
            'message': 'File uploaded to Google Drive successfully',
            'drive_file_id': drive_file_id
        }), 201
        
    except Exception as e:
        logger.error(f"Error uploading to Google Drive: {e}")
        return jsonify({'error': 'Failed to upload to Google Drive'}), 500

@app.route('/api/drive/download/<string:user_id>/<string:file_id>', methods=['GET'])
def download_from_google_drive(user_id, file_id):
    """Download encrypted file from Google Drive."""
    try:
        db = get_db()
        file_data = db.execute('''
            SELECT google_drive_file_id, original_file_name, storage_location
            FROM wrapped_keys
            WHERE user_id = ? AND file_id = ? AND storage_location = 'google_drive'
        ''', (user_id, file_id)).fetchone()
        
        if not file_data:
            return jsonify({'error': 'File not found or not stored on Google Drive'}), 404
        
        service = get_drive_service(user_id)
        if not service:
            return jsonify({'error': 'Google Drive not connected'}), 401
        
        encrypted_content = download_from_drive(service, file_data['google_drive_file_id'])
        
        return send_file(
            io.BytesIO(encrypted_content),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f"encrypted_{file_data['original_file_name']}.enc"
        )
        
    except Exception as e:
        logger.error(f"Error downloading from Google Drive: {e}")
        return jsonify({'error': 'Failed to download from Google Drive'}), 500

@app.route('/api/drive/status/<string:user_id>', methods=['GET'])
def google_drive_status(user_id):
    """Check if user has Google Drive connected."""
    try:
        db = get_db()
        user = db.execute(
            'SELECT google_drive_token FROM users WHERE user_id = ?', 
            (user_id,)
        ).fetchone()
        
        is_connected = bool(user and user['google_drive_token'])
        return jsonify({'connected': is_connected}), 200
    except Exception as e:
        logger.error(f"Error checking Drive status: {e}")
        return jsonify({'error': 'Failed to check Google Drive status'}), 500

@app.route('/api/drive/disconnect/<string:user_id>', methods=['POST'])
def disconnect_google_drive(user_id):
    """Disconnect Google Drive for user."""
    try:
        db = get_db()
        db.execute(
            'UPDATE users SET google_drive_token = NULL WHERE user_id = ?',
            (user_id,)
        )
        db.commit()
        return jsonify({'message': 'Google Drive disconnected successfully'}), 200
    except Exception as e:
        logger.error(f"Error disconnecting Drive: {e}")
        return jsonify({'error': 'Failed to disconnect Google Drive'}), 500

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
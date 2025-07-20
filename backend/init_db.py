# backend/init_db.py
import sqlite3
import os

# Database file path
# This ensures the database file is created in the same directory as the script.
DATABASE = os.path.join(os.path.dirname(__file__), 'dissertation.db')

def init_database():
    """
    Initializes the SQLite database.
    
    This function creates the necessary tables ('users' and 'wrapped_keys')
    for the application to function correctly. It includes an interactive
    prompt to recreate the database if it already exists.
    """
    
    # Check if the database file already exists.
    if os.path.exists(DATABASE):
        # Ask the user for confirmation before deleting the existing database.
        response = input(f"Database file '{DATABASE}' already exists. Do you want to recreate it? (y/N): ")
        if response.lower() == 'y':
            os.remove(DATABASE)
            print("Existing database removed.")
        else:
            print("Keeping existing database. Initialization aborted.")
            return
            
    # Establish a connection to the SQLite database file.
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # --- Create users table ---
    # This table stores user credentials.
    print("Creating 'users' table...")
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # --- Create wrapped_keys table ---
    # This table stores encrypted file metadata and the encrypted file data itself.
    # The 'encrypted_data' column is added to store the file content as a BLOB.
    print("Creating 'wrapped_keys' table with 'encrypted_data' column...")
    cursor.execute('''
        CREATE TABLE wrapped_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            file_id TEXT NOT NULL,
            wrapped_key TEXT NOT NULL,
            iv TEXT NOT NULL,
            salt TEXT NOT NULL,
            key_wrapping_iv TEXT NOT NULL,
            original_file_name TEXT NOT NULL,
            encrypted_data BLOB NOT NULL, -- This new column stores the encrypted file content
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, file_id),
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    
    # --- Create indexes for better query performance ---
    print("Creating indexes...")
    cursor.execute('CREATE INDEX idx_users_username ON users(username)')
    cursor.execute('CREATE INDEX idx_users_user_id ON users(user_id)')
    cursor.execute('CREATE INDEX idx_wrapped_keys_user_id ON wrapped_keys(user_id)')
    cursor.execute('CREATE INDEX idx_wrapped_keys_file_id ON wrapped_keys(file_id)')
    
    # Commit the changes to the database and close the connection.
    conn.commit()
    conn.close()
    
    print("-" * 30)
    print(f"Database initialized successfully at: {DATABASE}")
    print("Tables created:")
    print("- users")
    print("- wrapped_keys (now with 'encrypted_data' column)")
    print("- Associated indexes")

if __name__ == '__main__':
    # This allows the script to be run directly from the command line to set up the database.
    init_database()

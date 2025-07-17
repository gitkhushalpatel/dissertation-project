# backend/init_db.py
import sqlite3
import os

# Database file path
DATABASE = os.path.join(os.path.dirname(__file__), 'dissertation.db')

def init_database():
    """Initialize the SQLite database with required tables."""
    
    # Remove existing database file if it exists (optional - for fresh start)
    if os.path.exists(DATABASE):
        response = input(f"Database file '{DATABASE}' already exists. Do you want to recreate it? (y/N): ")
        if response.lower() == 'y':
            os.remove(DATABASE)
            print("Existing database removed.")
        else:
            print("Keeping existing database.")
            return
    
    # Create new database and tables
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create wrapped_keys table
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
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, file_id),
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    
    # Create indexes for better performance
    cursor.execute('CREATE INDEX idx_users_username ON users(username)')
    cursor.execute('CREATE INDEX idx_users_user_id ON users(user_id)')
    cursor.execute('CREATE INDEX idx_wrapped_keys_user_id ON wrapped_keys(user_id)')
    cursor.execute('CREATE INDEX idx_wrapped_keys_file_id ON wrapped_keys(file_id)')
    
    conn.commit()
    conn.close()
    
    print(f"Database initialized successfully at: {DATABASE}")
    print("Tables created:")
    print("- users")
    print("- wrapped_keys")
    print("- Associated indexes")

if __name__ == '__main__':
    init_database()
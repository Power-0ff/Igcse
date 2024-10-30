import sqlite3

# Step 1: Connect to SQLite Database (or create it if it doesn't exist)
conn = sqlite3.connect('feed.db')

# Step 2: Create a Cursor object to execute SQL queries
cursor = conn.cursor()

# Step 3: Create a Table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS Feed_Items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tag TEXT NOT NULL,
        category TEXT NOT NULL,
        views INTEGER
    )
''')

# Commit the changes and close the connection
conn.commit()
conn.close()

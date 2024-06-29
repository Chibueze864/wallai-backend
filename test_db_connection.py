import psycopg2

# Use the same connection details as in your database.py
conn_params = {
    "dbname": "users",
    "user": "postgres",  # Replace with your username
    "password": "djchibuezegmail",  # Replace with your password
    "host": "localhost",
    "port": "5432"
}

try:
    conn = psycopg2.connect(**conn_params)
    print("Successfully connected to the database!")
    conn.close()
except Exception as e:
    print(f"Unable to connect to the database. Error: {e}")

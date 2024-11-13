from flask import current_app
from flask_mysqldb import MySQL

mysql = MySQL()

def log_activity(user_id, action, details=None):
    cursor = mysql.connection.cursor()
    cursor.execute("""
        INSERT INTO activity_logs (user_id, action, details)
        VALUES (%s, %s, %s)
    """, (user_id, action, details))
    mysql.connection.commit()
    cursor.close()
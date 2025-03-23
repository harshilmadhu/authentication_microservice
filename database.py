import pymysql

#Replace the below DB credential with the valid one.
DB_HOST = "DB_HOSTNAME"
DB_USER = "DB_USERNAME"
DB_PASSWORD = "DB_PASSWORD"
DB_NAME = "DB_NAME"

def get_connection():
    connection = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )
    return connection


def create_user_table():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    first_name VARCHAR(100) NOT NULL,
                    last_name VARCHAR(100) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    phone VARCHAR(10) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    verification_token CHAR(36) NULL,
                    verified BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)
        conn.commit()
    finally:
        conn.close()

create_user_table()

from email.message import EmailMessage
import random
import smtplib
import ssl
import uuid
import bcrypt
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, status, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from config import smtp_email, smtp_password, smtp_server, smtp_port
from jwt_token import create_access_token, verify_access_token
import pymysql
from models import LoginWithOTP, Register, Login, ResetPassword, Update
from database import get_connection
from twilio.rest import Client
from config import ACCOUNT_SID, AUTH_TOKEN, TWILIO_PHONE_NUMBER

app = FastAPI()


pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto") # Used to hash the plain password while storing in DB.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login") #OAuth to authenticate logged_in user
otp_store = {}  # Store OTPs temporarily


@app.post('/register')
def register(data: Register, background_tasks: BackgroundTasks):
    """
    Registers a new user in the system.

    This endpoint validates the user input, checks if the email exist, checks if phone# has 10 digits valid number, 
    hashes the password, and inserts the user data into the database.

    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Validate phone number length
        if not data.phone.isdigit() or len(data.phone) != 10:
            raise ValueError("Invalid Phone Number. It must be exactly 10 digits and must contain only digits.")

        # Check if email or phone already exists
        cursor.execute("SELECT id FROM users WHERE email = %s OR phone = %s", (data.email, data.phone))
        if cursor.fetchone():
            raise ValueError("A user with this email or phone number already exists.")
        
        verification_token = str(uuid.uuid4())  # Generate verification token

        hashed_password = pwd_cxt.hash(data.password)

        # Insert user into the database
        user_insert = """
            INSERT INTO users (first_name, last_name, email, phone, password, verification_token, verified)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(user_insert, (data.first_name, data.last_name, data.email, data.phone, hashed_password, verification_token, False))
        conn.commit()

        # Send verification email asynchronously
        background_tasks.add_task(send_verification_email, data.email, verification_token, data.first_name)

        return {"message": f"User Created Successfully!!"}
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    except ConnectionError:
        raise HTTPException(status_code=500, detail="Database connection failed")

    except pymysql.MySQLError:
        raise HTTPException(status_code=500, detail="Database operation failed")

    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
    
    finally:
        cursor.close()
        conn.close()


@app.post('/login')
def login(data: Login):
    """
    
    Allow the user to Login with valid credentials and generates the bearer token.
    
    Will raise the exception if invalid credentials are entered
    
    """
    conn = get_connection()
    cursor = conn.cursor()  # Use dictionary cursor for named column access
    try:
        # Check if user exists
        query = """SELECT id, first_name, last_name, email, phone, password FROM users WHERE email = %s"""
        cursor.execute(query, (data.email,))  
        user = cursor.fetchone()

        if not user:
            return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"msg": "User does not exist"})

        # Verify password
        if not bcrypt.checkpw(data.password.encode('utf-8'), user['password'].encode('utf-8')):
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"msg": "Invalid password"})
        
        # Generate JWT token
        access_token = create_access_token(data={"sub": data.email})

        # Return user info
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user['id'],
                "first_name": user['first_name'],
                "last_name": user['last_name'],
                "email": user['email'],
                "phone": user['phone'],
                "password": user['password']
            }
        }

    except Exception as e:
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"msg": "An error occurred", "error": str(e)})
    finally:
        cursor.close()
        conn.close()


@app.put('/update')
def update(data: Update, token: str = Depends(oauth2_scheme)):
    """
    This endpoint will authenticate the logged in user and allow the user to modify their profile details.
    """

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Verify the JWT token
    payload = verify_access_token(token)
    if payload is None:
        raise credentials_exception

    user_email = payload.get("sub")  # Extract user email from token
    if not user_email:
        raise credentials_exception

    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Ensure the logged-in user is updating their own details
        if data.email != user_email:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You can only update your own account")

        logged_user = "SELECT * FROM users WHERE email = %s"
        cursor.execute(logged_user, (data.email,))
        user = cursor.fetchone()

        if not user:
            return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"msg": "User not found"})

        if len(data.phone) != 10 or not data.phone.isdigit():
            return JSONResponse(status_code=status.HTTP_411_LENGTH_REQUIRED, content={"msg": "Invalid Phone Number. It must be 10 digits."})
        
        hashed_password = pwd_cxt.hash(data.password)
        update_query = """UPDATE users SET first_name = %s, last_name = %s, phone = %s, password = %s WHERE email = %s"""
        cursor.execute(update_query, (data.first_name, data.last_name, data.phone, hashed_password, data.email))
        conn.commit()

        return JSONResponse(status_code=status.HTTP_200_OK, content={"msg": "User details updated successfully!"})
    
    except Exception as e:
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"msg": "An error occurred", "error": str(e)})
    
    finally:
        cursor.close()
        conn.close()


# Function to send verification email
def send_verification_email(email: str, token: str, name: str):
    """Below Code is for the Email Verification when user registers."""
    sender_email = smtp_email
    sender_password = smtp_password
    subject = "Verify Your Email"
    verification_link = f"http://127.0.0.1:8000/verify-email?token={token}"
    
    message = f"""\
Subject: {subject}

Hello {name},

Click the link below to verify your email:

{verification_link}

If you did not sign up, please ignore this email.
"""

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, message)
    except Exception as e:
        print(f"Error sending email: {e}")



@app.get("/verify-email")
def verify_email(token: str):
    """
    Verifies the email with the link sent to user and updated the verified status to True 
    if link is valid else will throw link expired exception.
    """
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT email FROM users WHERE verification_token = %s AND verified = False", (token,))
        user = cursor.fetchone()

        if not user:
            return {"message": "Invalid or expired verification link."}

        cursor.execute("UPDATE users SET verified = True WHERE verification_token = %s", (token,))
        conn.commit()

        return {"message": "Email verified successfully. You can now log in."}

    except Exception as e:
        conn.rollback()
        return {"error": "Verification failed"}

    finally:
        cursor.close()
        conn.close()


@app.post("/login_with_otp")
def login_with_otp(data: LoginWithOTP):
    """Allows user to login with the OTP sent to their phone number on SMS."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, first_name, last_name, email, phone FROM users WHERE phone = %s", (data.phone,))
        user = cursor.fetchone()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        otp = str(random.randint(100000, 999999))  # Generate a 6-digit OTP
        otp_store[data.phone] = otp  # Store OTP temporarily

        send_otp_via_sms(data.phone, otp)  # Send OTP

        return {"message": "OTP sent successfully"}
    
    except Exception as e:
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"msg": "An error occurred", "error": str(e)})
    
    finally:
        cursor.close()
        conn.close()

@app.post("/verify_otp")
def verify_otp(phone: str, otp: str):
    """
    Verifes if the sent OTP is same as OTP entered by user. 
    If it is same then user successfully logs in with the bearer token. If not valid OTP then throws exception.
    """
    if phone not in otp_store or otp_store[phone] != otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    del otp_store[phone]  # Remove OTP after successful verification
    
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, first_name, last_name, email, phone FROM users WHERE phone = %s", (phone,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        access_token = create_access_token(data={"sub": user['email']})
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user['id'],
                "first_name": user['first_name'],
                "last_name": user['last_name'],
                "email": user['email'],
                "phone": user['phone']
            },
            "msg": "OTP verified successfully."
        }
    finally:
        cursor.close()
        conn.close()


def send_otp_via_sms(phone: str, otp: str):
    """Sends OTP via SMS to the phone number provided by the user"""
    client = Client(ACCOUNT_SID, AUTH_TOKEN)
    message = client.messages.create(
        body=f"Your OTP code is {otp}",
        from_=TWILIO_PHONE_NUMBER,
        to=phone
    )
    print(f"OTP sent: {message.sid}")
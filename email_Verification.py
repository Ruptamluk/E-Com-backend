import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import random
import string

def generate_otp(length=6):
    """Generate a random OTP."""
    return ''.join(random.choices(string.digits, k=length))

def send_email(to_addr: str, subject: str, body: str):
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    USERNAME = os.getenv('EMAIL_USERNAME', 'coaching.rup.cse@gmail.com')
    PASSWORD = os.getenv('EMAIL_PASSWORD', 'alga ehyo fnpg jyst')

    if not USERNAME or not PASSWORD:
        raise ValueError("EMAIL_USERNAME and EMAIL_PASSWORD must be set in environment variables.")

    from_addr = USERNAME

    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(USERNAME, PASSWORD)
            server.send_message(msg)
            print("Email sent successfully!")
    except smtplib.SMTPAuthenticationError:
        print("Authentication Error: Check your email and password.")
    except smtplib.SMTPConnectError:
        print("Connection Error: Unable to connect to the SMTP server.")
    except smtplib.SMTPRecipientsRefused:
        print("Recipient Error: The recipient's address was refused.")
    except smtplib.SMTPDataError:
        print("Data Error: The server responded with an unexpected error.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

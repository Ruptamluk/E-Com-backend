import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os

# Environment variables for email credentials (set these in your environment)
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
USERNAME = os.getenv('EMAIL_USERNAME', 'mailto:coaching.rup.cse@gmail.com')
PASSWORD = os.getenv('EMAIL_PASSWORD', 'alga ehyo fnpg jyst')

# Email content
from_addr = USERNAME
to_addr = 'mailto:r.rupayankolkata@gmail.com'
subject = 'verification code sent successfully'
body = 'This is a test email sent from e_com_site!'

# Create the email message
msg = MIMEMultipart()
msg['From'] = from_addr
msg['To'] = to_addr
msg['Subject'] = subject
msg.attach(MIMEText(body, 'plain'))

# Send the email
try:
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()  # Secure the connection
    server.login(USERNAME, PASSWORD)
    server.send_message(msg)
    print("Medicine Delivery Attempted!")
except Exception as e:
    print(f"Error: {e}")

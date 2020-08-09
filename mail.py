import smtplib, ssl
import config
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

context = ssl.create_default_context()
port = 587

def send_message(to_email, subject, text):
    message = MIMEMultipart("alternative")

    html_text = MIMEText(text, "html")
    message["Subject"] = "Dashboard message"
    message["From"] = config.MAIL_ADDRESS
    message["To"] = to_email

    message.attach(html_text)
    with smtplib.SMTP(config.MAIL_SERVER, port) as server:
        server.starttls(context=context)
        server.login(config.MAIL_ADDRESS, config.MAIL_PASSWORD)

        server.sendmail(config.MAIL_ADDRESS, to_email, message.as_string())

import smtplib, ssl
import _thread
import config
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

context = ssl.create_default_context()
port = 587

def send_message(to_email, subject, text):
    message = MIMEMultipart("alternative")

    html_text = MIMEText(text, "html")
    message["Subject"] = subject
    message["From"] = config.MAIL_ADDRESS
    message["To"] = to_email

    message.attach(html_text)
    try:
        with smtplib.SMTP(config.MAIL_SERVER, port) as server:
            server.starttls(context=context)
            server.login(config.MAIL_ADDRESS, config.MAIL_PASSWORD)
            server.sendmail(config.MAIL_ADDRESS, to_email, message.as_string())
    except:
        print ("Error: Could not send email")

def send_text_message(to_email, subject, file_name, replacements):
    file = open(file_name)
    text = file.read()
    file.close()
    text = text.format(**replacements)
    try:
        _thread.start_new_thread(send_message, (to_email, subject, text, ))
    except:
        print ("Error: Could not spawn sendmail thread")

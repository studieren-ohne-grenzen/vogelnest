import smtplib, ssl
import _thread
import config
from email.mime.text import MIMEText
from email.mime.text import MIMEImage
from email.mime.multipart import MIMEMultipart

context = ssl.create_default_context()
port = 587

def compose_and_send(to_email, subject, text, html=None):
    if (html is not None):
        message = MIMEMultipart("related")
        message_alt = MIMEMultipart("alternative")
        message.attach(message_alt)
    else:
        message = MIMEText(text)

    message["Subject"] = subject
    message["From"] = config.MAIL_ADDRESS
    message["To"] = to_email
    
    if (html is not None):
        text_part = MIMEText(text, "plain")
        message_alt.attach(text_part)
        html_part = MIMEText(html, "html")
        message_alt.attach(html_part)
        logo_file = open('logo_sog.png', 'rb')
        logo = MIMEImage(logo_file.read())
        logo_file.close()
        logo.add_header('Content-ID', '<logo_sog>')
        message.attach(logo)

    try:
        with smtplib.SMTP(config.MAIL_SERVER, port) as server:
            server.starttls(context=context)
            server.login(config.MAIL_ADDRESS, config.MAIL_PASSWORD)
            server.sendmail(config.MAIL_ADDRESS, to_email, message.as_string())
    except:
        print ("Error: Could not send email")

def send_email(to_email, subject, file_name, replacements):
    try:
        htmlfile = open(file_name + '.html')
        html = htmlfile.read()
        htmlfile.close()
        stylefile = open('style.css')
        style = stylefile.read()
        stylefile.close()
        # TODO: add styling to replacements
        html = html.format(**replacements)
    except:
        print ("Error: Could not parse html mail template. Trying to send plain text mail instead")
        html=None
    
    try:
        textfile = open(file_name + '.txt')
        text = textfile.read()
        textfile.close()
        text = text.format(**replacements)
    except:
        print ("Error: Could not parse text mail template")
    else:
        try:
            _thread.start_new_thread(compose_and_send, (to_email, subject, text, html, ))
        except:
            print ("Error: Could not spawn sendmail thread")

__author__ = "Ashraf"

from flask import request
from flask import render_template
from flask_mail import Mail,Message
from flask import Flask
from src.encrypt import encryption

app = Flask(__name__)
mail = Mail(app)

app.config.update(
    DEBUG=True,
    # EMAIL SETTINGS
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME='xxxxxxxx@gmail.com',
    MAIL_PASSWORD='password_goes_here'
)


@app.route("/")
def index():
    return render()

mail = Mail(app)
@app.route("/mailsent", methods=['POST'])
def send():
    global mail
    subject = request.form['subject']
    recipient = request.form['recipient'] #get the recipient list
    key = request.form['key']  # get the body of the mail
    message_body = request.form['mailbody'] # get the body of the mail
    print("{}\n{}\n{}".format(subject,recipient,message_body))
    if "," in recipient:
        recipient_list = recipient.split(",")
        msg = Message(subject, sender='xxxxxxxx@gmail.com', recipients=recipient_list)
        msg.body = message_body
        mail.send(msg)
    else:
        recipient = recipient.split()
        print(recipient)
        msg = Message(subject, sender='xxxxxxxx@gmail.com', recipients=recipient)
        msg.body = encryption.message_encrypt(key, message_body)
        mail.send(msg)
    return "Sent"

@app.route("/send", methods = ['POST'])
def render():
    return render_template("sendmail.html")


if __name__ == "__main__":
    app.run(port=6555)

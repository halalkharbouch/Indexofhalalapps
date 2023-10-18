from morse_code_conveter import MorseCode
from flask import Flask, render_template, request, url_for, redirect, send_file, flash
from io import BytesIO
import sqlalchemy.exc
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
import smtplib

MY_EMAIL = 'initialisingben@gmail.com'
MY_PASSWORD = 'pglqseklmynfasop'

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'

# Connect DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///iha.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


#Setup Login Manager

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Configure Tables

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)


class App(db.Model):
    __tablename__ = 'apps'
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(250), nullable=False, unique=True)
    app_description = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    app_url_for = db.Column(db.String(250), nullable=False)


class NewsLetter(db.Model):
    __tablename__ = 'news letter users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)


with app.app_context():
    db.create_all()





@app.route("/")
def home():
    apps = App.query.all()
    return render_template('index.html', apps=apps)

@app.route('/all-apps')
def all_apps():
    apps = App.query.all()
    return render_template('all-apps.html', apps=apps)

@app.route('/contact-us', methods=['POST', 'GET'])
def contact_us():
    if request.method == 'POST':
        with smtplib.SMTP_SSL('smtp.gmail.com') as connection:
            connection.login(user=MY_EMAIL, password=MY_PASSWORD)
            connection.sendmail(from_addr=MY_EMAIL,
                                to_addrs='binyaminbgod@gmail.com',
                                msg=f'Subject:Message From Index of Halal Apps\n\n'
                                    f'Name: {request.form.get("name")}\n'
                                    f'Email: {request.form.get("email")}\n'
                                    f'Message: {request.form.get("message")}')
            flash("Your Message was sent successfully")
            return redirect(url_for('contact_us'))
    return render_template('contacts.html')

@app.route("/register", methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        try:

            new_user = User(email=request.form.get('email'),
                            name=request.form.get('name'),
                            password=generate_password_hash(password=request.form.get('password'), method='pbkdf2:sha256', salt_length=8))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
        except sqlalchemy.exc.IntegrityError:
            flash("Email address already exist! please login to continue")
            return redirect(url_for('login'))
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if not user or not check_password_hash(user.password, request.form.get('password')):
            flash("Invalid Credentials")
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html')


@app.route('/add-app', methods=['POST', 'GET'])
def add_app():
    if request.method == 'POST':
        new_app = App(app_name=request.form.get('app_name'),
                      app_description=request.form.get('app_description'),
                      img_url=request.form.get('img_url'),
                      app_url_for=request.form.get('app_url_for'))
        db.session.add(new_app)
        db.session.commit()
        flash("App Added Successfully")
        return redirect(url_for('all_apps'))
    return render_template('add-app.html')


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/text-to-morse', methods=['POST', 'GET'])
def text_to_morse():
    code = ''
    if request.method == 'POST':
        morse = MorseCode()
        morse_code = morse.text_to_morse(request.form['text'])
        code = morse_code
    return render_template('text-to-morse.html', morse_code=code)


@app.route('/download', methods=['POST', 'GET'])
def download():
    if request.method == 'POST':
        code = request.args.get('code')
        output = BytesIO()
        output.write(code.encode('utf-8'))
        output.seek(0)

        return send_file(output, as_attachment=True, download_name='code.txt', mimetype='text/plain')
    return redirect(url_for('home'))


@app.route('/subscribe-to-newsletter', methods=['POST', 'GET'])
def subscribe_to_news_letter():
    if request.method == 'POST':
        try:
            new_subscriber = NewsLetter(email=request.form.get('email'))
            db.session.add(new_subscriber)
            db.session.commit()
            flash('You have subscribed to our news letter')
        except sqlalchemy.exc.IntegrityError:
            flash('You have already subscribe')
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)



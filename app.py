from flask import Flask, render_template, session, redirect, request, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
import os
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask_migrate import Migrate
from dotenv import load_dotenv
from openai import OpenAI
load_dotenv()
app = Flask(__name__, static_url_path='/static', static_folder='static')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
db = SQLAlchemy(app)
migrate = Migrate(app, db)
api_key=os.getenv('OPENAI_API_KEY')
client=OpenAI(api_key=api_key)
# Configuration for email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'igatajohn15@gmail.com'
app.config['MAIL_PASSWORD'] = 'vqvq zdef tweu nytn'
app.config['MAIL_DEFAULT_SENDER'] = 'igatajohn15@gmail.com'
app.config['SECURITY_PASSWORD_SALT'] = 'e33f8aa37685ca765b9d5613c0e41c0b'
mail = Mail(app)

# Secret key for generating reset tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    def __repr__(self):
        return f'<User {self.username}>'
# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
@app.route('/users')
def user_list():
    users = User.query.all()
    return render_template('users.html', users=users)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please use a different email.', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Password and Confirm Password do not match.', 'error')
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)
        new_user = User(first_name=first_name, last_name=last_name, email=email, password=password_hash)
        db.session.add(new_user)
        db.session.commit()

        flash('You have successfully registered!', 'success')
        return redirect(url_for('successful_register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('vitals'))
        else:
            flash('Invalid email or password. Please try again.', 'error')

    return render_template('login.html')

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            send_password_reset_email(user)
            flash('A password reset email has been sent.', 'info')
        else:
            flash('No account associated with this email.', 'error')
        return redirect(url_for('password_reset_mail_sent'))
    return render_template('recover.html')

def send_password_reset_email(user):
    token = generate_reset_token(user)
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = Message(
        subject="Password Reset Request",
        recipients=[user.email],
        body=f"To reset your password, visit the following link: {reset_url}\n\n"
             "If you did not make this request, please ignore this email."
    )
    try:
        mail.send(msg)
        print(f"Sent email to {user.email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

def generate_reset_token(user):
    return serializer.dumps(user.email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_reset_token(token, expiration=3600):
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email
@app.route('/get-response', methods=['POST'])
def get_response():
    try:
        data = request.json
        user_input = data.get('input', '')
        if not user_input:
            raise ValueError("No input provided")
        
        response_text = generate_response(user_input)
        return jsonify({'response': response_text})
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = confirm_reset_token(token)
    if not email:
        flash('The reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('reset_password', token=token))

        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('new_password_set'))

    return render_template('reset_password.html', token=token)

@app.route('/password_reset_mail_sent')
def password_reset_mail_sent():
    return render_template('password_reset_mail_sent.html')

@app.route('/new_password_set')
def new_password_set():
    return render_template('new_password_set.html')
@app.route('/chatbot', methods=['POST'])
def chatbot():
    data = request.json
    user_input = data.get('message', '')

    response = generate_response(user_input)
    
    return jsonify({'reply': response})
def generate_response(user_input):
    try:
        # Create a chat completion using the fine-tuned GPT-3.5 Turbo model
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are Quantum Doctor, a healthcare assistant, capable of making diagnosis based on symptoms,make sure to explain diagnosis in the simplest possible way for patients to understand. You were trained by a team of  Machine Learning Engineers led by Engineer Igata John at QuantumLabs, a division of Quantum Innovative Tech Solutions Ltd"},
                {"role": "user", "content": user_input}
            ]
        )

        # Extract the model's response content
        model_response = completion.choices[0].message.content.strip()

        return model_response
    except Exception as e:
        return str(e)

@app.route('/')
@login_required
def vitals():
    return render_template('vitals.html')

@app.errorhandler(401)
def unauthorized(error):
    return render_template('unauthorize.html'), 401

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/consultations')
def consultations():
    return render_template('consultations.html')
@app.route('/consultations/questions')
def consultation_question():
    return render_template('consultation_question.html')
@app.route('/consultations/results')
def consultation_result():
    return render_template('consultation_result.html')
@app.route('/successful_register')
def successful_register():
    return render_template('successful_register.html')

@app.route('/diagnosis')
def diagnosis():
    return render_template('diagnosis.html')

@app.route('/logout')
@login_required
def logout():
   logout_user()
   flash('Logged out successfully!', 'success')
   return redirect(url_for('login'))

if __name__=='__main__':
    app.run(debug=True, host='0.0.0.0', port='5000')

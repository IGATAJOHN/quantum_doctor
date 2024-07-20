from flask import Flask, render_template, session, redirect, request, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
import os
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask_migrate import Migrate
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from datetime import datetime
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains import LLMChain, ConversationChain
from langchain.memory import ConversationBufferMemory
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import smtplib
load_dotenv()
app = Flask(__name__, static_url_path='/static', static_folder='static')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
db = SQLAlchemy(app)
migrate = Migrate(app, db)
api_key=os.getenv('OPENAI_API_KEY')
UPLOAD_FOLDER = 'uploads/'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
client=ChatOpenAI(api_key=api_key)
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

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<User {self.first_name} {self.last_name}>'

class ChatHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_bot = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('chat_history', lazy=True))

class DoctorRating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to Doctor
    doctor = db.relationship('Doctor', back_populates='ratings')
    # Relationship to User
    user = db.relationship('User', back_populates='ratings')

    def __repr__(self):
        return f'<DoctorRating {self.doctor_id} - {self.rating}>'

class Specialty(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)

class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    specialization = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    avatar = db.Column(db.String(200), nullable=True)
    medical_license = db.Column(db.String(200), nullable=True)
    educational_certificate = db.Column(db.String(200), nullable=True)
    photo_id = db.Column(db.String(200), nullable=True)
    nafdac_id = db.Column(db.String(200), nullable=True)

    ratings = db.relationship('DoctorRating', back_populates='doctor')

    def __repr__(self):
        return f'<Doctor {self.name}>'

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
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            # Generate OTP
            otp = random.randint(1000, 9999)
            session['otp'] = otp
            session['user_id'] = user.id

            # Send OTP to user's email
            send_otp_email(user.email, otp)

            flash('OTP sent to your email. Please verify.', 'info')
            return redirect(url_for('otp_verify'))
        else:
            flash('Invalid email or password. Please try again.', 'error')

    return render_template('login.html')
@app.route('/otp_verify', methods=['GET', 'POST'])
def otp_verify():
    if request.method == 'POST':
        otp_input = request.form['otp']
        if otp_input == str(session.get('otp')):
            user = User.query.get(session['user_id'])
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('vitals'))
        else:
            flash('Invalid OTP. Please try again.', 'error')
    return render_template('otp.html')
def send_otp_email(to_email, otp):
    from_email = app.config['MAIL_USERNAME']
    from_password = app.config['MAIL_PASSWORD']
    smtp_server = app.config['MAIL_SERVER']
    smtp_port = app.config['MAIL_PORT']

    subject = 'Your OTP Code'
    body = f'Your OTP code is {otp}.'

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(from_email, from_password)
            server.sendmail(from_email, to_email, msg.as_string())
        print("OTP email sent successfully!")
    except smtplib.SMTPException as e:
        print(f"SMTP error occurred: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
@app.route('/user-appointments', methods=['GET'])
@login_required
def user_appointments():
    appointments = [
        {
            'time': '08:30 am - 10:30 am',
            'title': 'Annual Visit 15',
            'doctor': 'Dr. Donald F. Watren'
        }
        # Add more appointments as needed
    ]
    return jsonify({'appointments': appointments})
@app.route('/user-profile', methods=['GET'])
@login_required
def user_profile():
    user = {
        'name': current_user.name,
        'blood_type': 'O+',
        'height': 186,
        'weight': 90,
        'age': 25,
        'location': 'Abuja, Nigeria',
        'avatar': '/static/images/avatar-default.png'  # Example avatar
    }
    return jsonify(user)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
# Route to add doctors
@app.route('/api/add_doctor', methods=['POST'])
def add_doctor():
    data = request.form
    files = request.files

    # Extract doctor data from the form
    name = data.get('name')
    specialization = data.get('specialization')
    location = data.get('location')
    avatar = files.get('avatar')
    medical_license = files.get('medical_license')
    board_certifications = files.getlist('board_certifications')
    educational_certificate = files.get('educational_certificate')
    photo_id = files.get('photo_id')
    nafdac_id = files.get('nafdac_id')

    # Validate and save files
    def save_file(file, subfolder):
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], subfolder, filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            file.save(filepath)
            return filepath
        return None

    avatar_path = save_file(avatar, 'avatars') if avatar else None
    medical_license_path = save_file(medical_license, 'licenses') if medical_license else None
    board_certifications_paths = [save_file(cert, 'certifications') for cert in board_certifications if cert and allowed_file(cert.filename)]
    educational_certificate_path = save_file(educational_certificate, 'education') if educational_certificate else None
    photo_id_path = save_file(photo_id, 'photo_ids') if photo_id else None
    nafdac_id_path = save_file(nafdac_id, 'nafdac_ids') if nafdac_id else None

    # Create a new Doctor object
    new_doctor = Doctor(
        name=name,
        specialization=specialization,
        location=location,
        avatar=avatar_path,
        medical_license=medical_license_path,
        educational_certificate=educational_certificate_path,
        photo_id=photo_id_path,
        nafdac_id=nafdac_id_path
    )
    db.session.add(new_doctor)
    db.session.commit()

    return jsonify({"message": "Doctor added successfully", "doctor_id": new_doctor.id}), 201
@app.route('/rate-doctor', methods=['POST'])
@login_required
def rate_doctor():
    data = request.json
    doctor_name = data['doctor_name']
    rating = int(data['rating'])

    # Create a new rating entry
    new_rating = DoctorRating(doctor_name=doctor_name, user_id=current_user.id, rating=rating)
    db.session.add(new_rating)
    db.session.commit()

    return jsonify({'success': True})
@app.route('/doctor-rating/<int:doctor_id>', methods=['GET'])
def get_doctor_rating(doctor_id):
    average_rating = db.session.query(func.avg(DoctorRating.rating)).filter_by(doctor_id=doctor_id).scalar()
    return jsonify({"average_rating": round(average_rating, 1)})
@app.route('/specialties', methods=['GET'])
def get_specialties():
    specialties = Specialty.query.all()
    return jsonify([specialty.name for specialty in specialties])
@app.route('/add-specialty', methods=['POST'])
def add_specialty():
    from flask import request, jsonify
    name = request.json.get('name')
    if not name:
        return jsonify({'error': 'Specialty name is required'}), 400
    specialty = Specialty(name=name)
    db.session.add(specialty)
    db.session.commit()
    return jsonify({'message': 'Specialty added successfully'}), 201
# Example route to verify a doctor
@app.route('/verify-doctor/<int:doctor_id>', methods=['POST'])
def verify_doctor(doctor_id):
    doctor = Doctor.query.get(doctor_id)
    if not doctor:
        return jsonify({'error': 'Doctor not found'}), 404
    doctor.verified = True
    db.session.commit()
    return jsonify({'message': 'Doctor verified successfully'})
@app.route('/')
@app.route('/login-page')
def login_page():
    return render_template('login.html')
@app.route('/otp-page')
def otp_page():
    return render_template('otp.html')
# OTP generation
def generate_otp():
    return str(random.randint(1000, 9999))
@app.route('/otp')
def otp():
    return render_template('otp.html')

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
@login_required
def chatbot():
    data = request.json
    user_input = data.get('message', '')
    
    if not user_input:
        return jsonify({'error': 'No message provided'}), 400
    
    # Store user message
    user_message = ChatHistory(user_id=current_user.id, message=user_input, is_bot=False)
    db.session.add(user_message)
    db.session.commit()
    
    # Generate response
    response = generate_response(user_input)
    
    # Store bot response
    bot_message = ChatHistory(user_id=current_user.id, message=response, is_bot=True)
    db.session.add(bot_message)
    db.session.commit()

    return jsonify({'reply': response})
template="""You are Quantum Doctor, a healthcare assistant, capable of making diagnosis based on symptoms. 
                You were trained by a team of  Machine Learning Engineers led by Engineer Igata John at QuantumLabs, 
                a division of Quantum Innovative Tech Solutions Ltd
                User: {user_input}
                Quantum Doctor:
                """
model = ChatOpenAI(model_name='gpt-3.5-turbo')
parser = StrOutputParser()
prompt= ChatPromptTemplate.from_messages(
 [
    ("system",template),
    ("user",'{user_input}')
 ]

)

chains= prompt | model | parser
# chains=LLMChain(prompt=prompt,llm=model)
def history(user_input):
    memory = ConversationBufferMemory()
    conversation = ConversationChain(
    llm=model,
    memory=memory,
    )
    generate_response(user_input)
    history=conversation.predict(input=user_input)
    return history
def generate_response(user_input):
    try:
        # Generate the response using the LLMChain
        response = chains.invoke({"user_input":user_input})
        print(response)
        return response
    except Exception as e:
        return str(e)

@app.route('/vitals')
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

# app.py
@app.route('/diagnosis', methods=['GET'])
@login_required
def diagnosis():
    chat_history = ChatHistory.query.filter_by(user_id=current_user.id).order_by(ChatHistory.timestamp).all()
    return render_template('diagnosis.html', chat_history=chat_history)

# app.py
@app.route('/chat-history', methods=['GET'])
@login_required
def chat_history():
    history = ChatHistory.query.filter_by(user_id=current_user.id).order_by(ChatHistory.timestamp).all()
    return jsonify([{
        'message': chat.message,
        'is_bot': chat.is_bot,
        'timestamp': chat.timestamp.isoformat()
    } for chat in history])

@app.route('/logout')
@login_required
def logout():
   logout_user()
   flash('Logged out successfully!', 'success')
   return redirect(url_for('login'))

if __name__=='__main__':
    app.run(debug=True, host='0.0.0.0', port='5000')

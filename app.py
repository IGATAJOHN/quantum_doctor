from flask import (
    Flask,
    render_template,
    session,
    redirect,
    request,
    url_for,
    flash,
    jsonify,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    UserMixin,
    current_user,
)
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime
from flask_socketio import SocketIO, join_room, leave_room, send
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from openai import OpenAI
import random
load_dotenv()
app = Flask(__name__, static_url_path="/static", static_folder="static")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
db = SQLAlchemy(app)
# Define a path to save uploaded files
UPLOAD_FOLDER = "static/uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
migrate = Migrate(app, db)
api_key = os.getenv("OPENAI_API_KEY")
socketio = SocketIO(app, cors_allowed_origins="*")
client = OpenAI(api_key=api_key)
# Configuration for email
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = "igatajohn15@gmail.com"
app.config["MAIL_PASSWORD"] = "vqvq zdef tweu nytn"
app.config["MAIL_DEFAULT_SENDER"] = "igatajohn15@gmail.com"
app.config["SECURITY_PASSWORD_SALT"] = "e33f8aa37685ca765b9d5613c0e41c0b"
mail = Mail(app)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# Secret key for generating reset tokens
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


class SentReceivedMessages(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    receiver_id = db.Column(db.Integer, db.ForeignKey("doctor.id"))
    message_id = db.Column(db.Integer, db.ForeignKey("message.id"))
    message = db.relationship("Message", backref="sent_received_messages")


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    messages = db.relationship(
        "Message",
        backref=db.backref("sent_messages", lazy=True),
    )

    def __repr__(self):
        return f"<User {self.username}>"


class DoctorRating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_name = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<DoctorRating {self.doctor_name} - {self.rating}>"


class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    specialization = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    avatar = db.Column(db.String(120), nullable=False)
    about = db.Column(db.Text, nullable=True)
    experience = db.Column(db.Text, nullable=True)
    contact = db.Column(db.String(100), nullable=True)
    rating = db.Column(db.Float, nullable=True)
    online = db.Column(db.Boolean, default=False)
    messages = db.relationship(
        "Message",
        backref=db.backref("received_messages", lazy=True),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "specialization": self.specialization,
            "location": self.location,
            "avatar": self.avatar,
            "online": self.online,
            "rating": self.rating,
            "about": self.about,
            "experience": self.experience,
            "contact": self.contact,
        }

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey("doctor.id"), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey("doctor.id"), nullable=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
    )
    receiver_id = db.Column(db.Integer, db.ForeignKey("doctor.id"), nullable=False)
    message_text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)


class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=False)
    sender_id = db.Column(db.Integer, nullable=False)
    message_text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)


with app.app_context():
    db.create_all()
# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route("/users")
def user_list():
    users = User.query.all()
    return render_template("users.html", users=users)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already exists. Please use a different email.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Password and Confirm Password do not match.", "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=password_hash,
        )
        db.session.add(new_user)
        db.session.commit()

        flash("You have successfully registered!", "success")
        return redirect(url_for("successful_register"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for("vitals"))
        else:
            flash("Invalid email or password. Please try again.", "error")

    return render_template("login.html")


@app.route("/api/messages", methods=["GET"])
def get_messages():
    user_id = request.args.get("user_id")
    messages = Message.query.filter(
        (Message.sender_id == user_id) | (Message.receiver_id == user_id)
    ).all()
    return jsonify(
        [
            {
                "id": msg.id,
                "sender_id": msg.sender_id,
                "receiver_id": msg.receiver_id,
                "message_text": msg.message_text,
                "timestamp": msg.timestamp,
                "is_read": msg.is_read,
            }
            for msg in messages
        ]
    )


@app.route("/api/messages/<int:message_id>/replies", methods=["POST"])
def send_reply(message_id):
    data = request.json
    new_reply = Reply(
        message_id=message_id,
        sender_id=data["sender_id"],
        message_text=data["message_text"],
    )
    db.session.add(new_reply)
    db.session.commit()
    return jsonify({"message": "Reply sent successfully"}), 201


@app.route("/api/book-appointment", methods=["POST"])
def book_appointment():
    try:
        data = request.get_json()
        appointment = Appointment(
            doctor_id=data["doctor_id"],
            user_id=data["user_id"],
            date=datetime.strptime(data["date"], "%Y-%m-%d").date(),
            time=datetime.strptime(data["time"], "%H:%M").time(),
        )
        db.session.add(appointment)
        db.session.commit()
        return jsonify({"success": True}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/recover", methods=["GET", "POST"])
def recover():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        if user:
            send_password_reset_email(user)
            flash("A password reset email has been sent.", "info")
        else:
            flash("No account associated with this email.", "error")
        return redirect(url_for("password_reset_mail_sent"))
    return render_template("recover.html")


def send_password_reset_email(user):
    token = generate_reset_token(user)
    reset_url = url_for("reset_password", token=token, _external=True)
    msg = Message(
        subject="Password Reset Request",
        recipients=[user.email],
        body=f"To reset your password, visit the following link: {reset_url}\n\n"
        "If you did not make this request, please ignore this email.",
    )
    try:
        mail.send(msg)
        print(f"Sent email to {user.email}")
    except Exception as e:
        print(f"Failed to send email: {e}")


def generate_reset_token(user):
    return serializer.dumps(user.email, salt=app.config["SECURITY_PASSWORD_SALT"])


@app.route("/api/favorite", methods=["POST"])
@login_required
def toggle_favorite():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid input"}), 400

        user_id = data.get("user_id")
        doctor_id = data.get("doctor_id")
        if not user_id or not doctor_id:
            return jsonify({"error": "Missing user_id or doctor_id"}), 400

        favorite = Favorite.query.filter_by(
            user_id=user_id, doctor_id=doctor_id
        ).first()
        if favorite:
            db.session.delete(favorite)
            db.session.commit()
            return jsonify({"favorite": False}), 200
        else:
            new_favorite = Favorite(user_id=user_id, doctor_id=doctor_id)
            db.session.add(new_favorite)
            db.session.commit()
            return jsonify({"favorite": True}), 201
    except Exception as e:
        app.logger.error(f"Error in toggle_favorite: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/favorite/<int:doctor_id>", methods=["POST"])
@login_required
def add_to_favorites(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)
    if doctor in current_user.favorites:
        return jsonify({"message": "Doctor already in favorites"}), 400
    try:
        current_user.favorites.append(doctor)
        db.session.commit()
        return jsonify({"message": "Doctor added to favorites"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/api/unfavorite/<int:doctor_id>", methods=["POST"])
@login_required
def remove_from_favorites(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)
    if doctor not in current_user.favorites:
        return jsonify({"message": "Doctor not in favorites"}), 400
    try:
        current_user.favorites.remove(doctor)
        db.session.commit()
        return jsonify({"message": "Doctor removed from favorites"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


def confirm_reset_token(token, expiration=3600):
    try:
        email = serializer.loads(
            token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=expiration
        )
    except:
        return False
    return email


@app.route("/get-response", methods=["POST"])
def get_response():
    try:
        data = request.json
        user_input = data.get("input", "")
        if not user_input:
            raise ValueError("No input provided")

        response_text = generate_response(user_input)
        return jsonify({"response": response_text})
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = confirm_reset_token(token)
    if not email:
        flash("The reset link is invalid or has expired.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("reset_password", token=token))

        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password)
            db.session.commit()
            flash("Your password has been updated!", "success")
            return redirect(url_for("new_password_set"))

    return render_template("reset_password.html", token=token)


@app.route("/password_reset_mail_sent")
def password_reset_mail_sent():
    return render_template("password_reset_mail_sent.html")


@app.route("/new_password_set")
def new_password_set():
    return render_template("new_password_set.html")


@app.route("/chatbot", methods=["POST"])
def chatbot():
    data = request.json
    user_input = data.get("message", "")

    response = generate_response(user_input)

    return jsonify({"reply": response})


def generate_response(user_input):
    try:
        # Create a chat completion using the fine-tuned GPT-3.5 Turbo model
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": """You are Quantum Doctor, a healthcare assistant, capable of making diagnosis based on symptoms,
                make sure to explain diagnosis in the simplest possible way for patients to understand.
                You were trained by a team of  Machine Learning Engineers led by Engineer Igata John at QuantumLabs, 
                a division of Quantum Innovative Tech Solutions Ltd
                """,
                },
                {"role": "user", "content": user_input},
            ],
        )

        # Extract the model's response content
        model_response = completion.choices[0].message.content.strip()

        return model_response
    except Exception as e:
        return str(e)


@app.route("/doctor/<int:doctor_id>")
def doctor_details(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)
    return render_template("details.html", doctor=doctor)


@app.route("/api/doctors", methods=["POST"])
def manage_doctors():
    name = request.form["name"]
    specialization = request.form["specialization"]
    location = request.form["location"]
    about = request.form["about"]
    experience = request.form["experience"]
    contact = request.form["contact"]

    avatar = request.files["avatar"]
    filename = secure_filename(avatar.filename)
    avatar_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    avatar.save(avatar_path)

    new_doctor = Doctor(
        name=name,
        specialization=specialization,
        location=location,
        about=about,
        experience=experience,
        contact=contact,
        avatar=f"uploads/{filename}",  # Store relative path
    )
    db.session.add(new_doctor)
    db.session.commit()

    return jsonify({"success": True}), 201


@app.route("/api/doctors", methods=["GET"])
def display_doctors():
    doctors = Doctor.query.all()
    return jsonify([doctor.to_dict() for doctor in doctors])


@app.route("/api/doctor/<int:doctor_id>", methods=["GET"])
def get_doctor_details(doctor_id):
    doctor = Doctor.query.get(doctor_id)

    if doctor:
        return (
            jsonify(
                {
                    "id": doctor.id,
                    "name": doctor.name,
                    "specialization": doctor.specialization,
                    "location": doctor.location,
                    "avatar": doctor.avatar,
                    "about": doctor.about,
                    "experience": doctor.experience,
                    "contact": doctor.contact,
                    "rating": doctor.rating,
                    "online": doctor.online,
                }
            ),
            200,
        )

    else:
        return jsonify({"error": "Doctor not found"}), 404


@app.route("/api/doctor/messages", methods=["GET"])
def get_doctor_messages():
    doctor_id = request.args.get("doctor_id")
    messages = get_messages_for_doctor(doctor_id)
    return jsonify(messages)


@app.route("/api/doctor/messages", methods=["POST"])
def send_doctor_message():
    data = request.json
    room = f"doctor_{data['receiver_id']}"
    socketio.emit("message", data["message"], room=room)
    save_message(data)
    return jsonify({"status": "success"})


def get_messages_for_doctor(doctor_id):
    messages = Message.query.filter_by(receiver_id=doctor_id).all()
    return [
        {
            "id": msg.id,
            "sender_id": msg.sender_id,
            "receiver_id": msg.receiver_id,
            "message_text": msg.message_text,
            "timestamp": msg.timestamp.isoformat(),
        }
        for msg in messages
    ]


def save_message(data):
    message = Message(
        sender_id=data["sender_id"],
        receiver_id=data["receiver_id"],
        message_text=data["message"],
    )
    db.session.add(message)
    db.session.commit()


@app.route('/notifications')
@login_required
def notifications():
    user_id = current_user.id
    notifications = get_notifications_for_user(user_id)
    return jsonify({"notifications": notifications})

def get_notifications_for_user(user_id):
    # Implement this function to fetch notifications for the user from your database
    notifications = [
        {"message": "Your appointment is confirmed for tomorrow."},
        {"message": "You have a new message from Dr. Jane."},
        {"message": "Remember to take your medication at 9 AM."},
    ]
    return notifications

def save_message(data):
    message = Message(
        sender_id=data['sender_id'],
        receiver_id=data['receiver_id'],
        message_text=data['message']
    )
    db.session.add(message)
    db.session.commit()
health_tips = [
    "Stay hydrated by drinking at least 8 glasses of water a day.",
    "Take regular breaks while working to stretch and move around.",
    "Include more fruits and vegetables in your diet.",
    "Get at least 7-8 hours of sleep each night.",
    "Exercise for at least 30 minutes a day."
]


@app.route('/')
@login_required
def vitals():
    today = datetime.today().date()
    health_tip = get_health_tip_for_day(today)
    return render_template('vitals.html', health_tip=health_tip)


def get_health_tip_for_day(date):
    random.seed(date.toordinal())
    return random.choice(health_tips)


@app.route("/rate-doctor", methods=["POST"])
@login_required
def rate_doctor():
    data = request.json
    doctor_name = data["doctor_name"]
    rating = int(data["rating"])

    # Create a new rating entry
    new_rating = DoctorRating(
        doctor_name=doctor_name, user_id=current_user.id, rating=rating
    )
    db.session.add(new_rating)
    db.session.commit()

    return jsonify({"success": True})


@app.errorhandler(401)
def unauthorized(error):
    return render_template("unauthorize.html"), 401


@socketio.on("join_room")
def handle_join_room_event(data):
    join_room(data["room"])
    send(data["username"] + " has entered the room.", to=data["room"])


@socketio.on("leave_room")
def handle_leave_room_event(data):
    leave_room(data["room"])
    send(data["username"] + " has left the room.", to=data["room"])


@socketio.on("send_message")
def handle_send_message_event(data):
    send(data["message"], to=data["room"])


@app.route("/profile")
def profile():
    return render_template("profile.html")


@app.route("/consultations")
def consultations():
    return render_template("consultations.html")


@app.route("/successful_register")
def successful_register():
    return render_template("successful_register.html")


@app.route("/diagnosis")
def diagnosis():
    return render_template("diagnosis.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    socketio.run(app, debug=True, host="0.0.0.0", port="5000")

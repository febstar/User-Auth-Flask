import werkzeug.security
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap5
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, InputRequired, NumberRange, Email


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CREATE DATABASE


class Base(DeclarativeBase):
    pass


login_manager = LoginManager()

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE TABLE IN DB


class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


# class RegisterForm(FlaskForm):
#     email = StringField(label='E-mail', validators=[InputRequired()])
#     name = StringField(label='Name', validators=[InputRequired()])
#     password = StringField(label="Password", validators=[InputRequired()])
#     submit = SubmitField(label='Register')


with app.app_context():
    db.create_all()

# Bootstrap5(app)

@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user = db.session.execute(db.select(User).where(User.email == request.form.get('email'))).scalar()
        if user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        hashed_salted = werkzeug.security.generate_password_hash(password=request.form.get('password'),
                                                                 method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            email=request.form.get('email'),
            password=hashed_salted,
            name=request.form.get('name')
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        user_id = db.session.execute(db.select(User).where(User.email == request.form.get('email'))).scalar()
        id = user_id.id
        return redirect(url_for('secrets', id=id))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_mail = request.form.get('email')
        user_password = request.form.get('password')
        result = db.session.execute(db.select(User).where(User.email == user_mail))
        user = result.scalar()
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, user_password):
            flash('Password Incorect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets', id=user.id))
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets/<int:id>', methods=["GET", "POST"])
@login_required
def secrets(id):
    user = db.get_or_404(User, id)
    return render_template("secrets.html", user=user, name=current_user.name, logged_in=True)


@app.route('/logout')
@login_required
def logout():
    pass


@app.route('/download', methods=["GET"])
@login_required
def download():
    return send_from_directory('static', path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)

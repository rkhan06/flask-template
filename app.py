from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import login_user, LoginManager, logout_user, login_required,\
    current_user

from config import Config


app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app=app, db=db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

from models import User
from forms import LoginForm, RegisterForm, PasswordResetForm


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    users = User.query.all()
    return render_template('index.html', users=users)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash("Invalid email or password")
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        flash("Welcome")
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User(name=form.name.data, email=form.email.data)
        new_user.set_password(raw_password=form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('You have successfully registered')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    form = PasswordResetForm()
    return render_template('reset-password.html', form=form)

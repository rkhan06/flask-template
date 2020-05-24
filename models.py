from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from app import login_manager
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(50))

    def __init__(self, email, name):
        self.email = email
        self.name = name

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)

    def __repr__(self):
        return '<User %r>' % (self.name)

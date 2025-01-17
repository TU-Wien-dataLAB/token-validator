from secrets import token_hex
from typing import Self

from authlib.oauth2.rfc6749 import OAuth2Token
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
from flask_admin.contrib.sqla.form import InlineOneToOneModelConverter
from flask_admin.model import InlineFormAdmin
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView

from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY  # Required for session management

db = SQLAlchemy(app)

oauth = OAuth(app)
oauth.register(
    name='oidc',
    client_id=Config.OIDC_CLIENT_ID,
    client_secret=Config.OIDC_CLIENT_SECRET,
    access_token_url=Config.OIDC_TOKEN_URL,
    authorize_url=Config.OIDC_AUTHORIZE_URL,
    server_metadata_url=Config.OIDC_CONFIGURATION_URL,
    client_kwargs={'scope': 'openid profile email'}
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)

    @classmethod
    def from_session(cls) -> Self | None:
        uid = session.get('user_id')
        return None if uid is None else db.session.get(cls, uid)


class TokenValidatorAdminView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    can_edit = True

    def is_accessible(self):
        user = User.from_session()
        return False if user is None else user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        # redirect to login page if user doesn't have access
        return redirect(url_for('/', next=request.url))


admin = Admin(app, name='admin')
admin.add_view(TokenValidatorAdminView(User, db.session))


def random_token(nbytes=32) -> str:
    """Generate a random token."""
    return token_hex(nbytes=nbytes)


def update_user_token(user: User):
    token = random_token()
    user.token = token
    db.session.commit()


@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return oauth.oidc.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    token: OAuth2Token = oauth.oidc.authorize_access_token()
    user = User.query.filter_by(email=token["userinfo"]["email"]).first()
    if not user:
        user = User(email=token["userinfo"]["email"], is_admin=False)
        update_user_token(user)
        db.session.add(user)
        db.session.commit()
    # always update admin status
    user.is_admin = Config.ADMIN_GROUP in token["userinfo"]["groups"]
    db.session.commit()

    session['user_id'] = user.id
    return redirect('/')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')


@app.route('/validate', methods=['GET', 'POST'])
def validate_token():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token_from_header = auth_header[7:]
        token_entry = User.query.filter_by(token=token_from_header).first()
        if token_entry:
            return jsonify({'message': 'Token is valid'}), 200
        else:
            return jsonify({'message': 'Token is invalid'}), 401
    else:
        return jsonify({'message': 'No Bearer token provided'}), 401


@app.route('/', methods=['GET'])
def token_page():
    """Display the current token on the page."""

    user: User | None = User.from_session()
    if user is None:
        return redirect(url_for('login'))
    return render_template('token.html', token=user.token)


@app.route('/regenerate-token', methods=['POST'])
def regenerate_token():
    """Generate a new token and update the 'database'."""
    user: User | None = User.from_session()
    if user is None:
        return redirect(url_for('login'))
    update_user_token(user)
    return redirect(url_for('token_page'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8000, debug=True)

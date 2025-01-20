from authlib.oauth2.rfc6749 import OAuth2Token
from flask import current_app, url_for, session, redirect

from validator.extensions import oauth, db
from validator.models import User
from validator.views import update_user_token
from config import Config


@current_app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return oauth.oidc.authorize_redirect(redirect_uri)


@current_app.route('/authorize')
def authorize():
    token: OAuth2Token = oauth.oidc.authorize_access_token()
    user = User.query.filter_by(email=token["userinfo"]["email"]).first()
    # TODO: add block list to db -> remove user from db if in block list and return 403
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


@current_app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

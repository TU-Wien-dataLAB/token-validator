from flask import Flask

from config import Config
from validator.extensions import db, admin, oauth, migrate


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.secret_key = Config.SECRET_KEY  # Required for session management

    db.init_app(app)
    admin.init_app(app)
    oauth.init_app(app)
    migrate.init_app(app, db)

    with app.app_context():
        from validator import views
        from validator import auth
        oauth.register(
            name='oidc',
            client_id=Config.OIDC_CLIENT_ID,
            client_secret=Config.OIDC_CLIENT_SECRET,
            access_token_url=Config.OIDC_TOKEN_URL,
            authorize_url=Config.OIDC_AUTHORIZE_URL,
            server_metadata_url=Config.OIDC_CONFIGURATION_URL,
            client_kwargs={'scope': 'openid profile email'}
        )

    return app


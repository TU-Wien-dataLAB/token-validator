import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    # External links are formatted by "|" to separate different links and ">" to separate names and URLs
    #   e.g. "Link 1>https://...|Link 2>https://..."
    EXTERNAL_LINKS = {
        k: v for k, v in (link.split(">", 1) for link in os.environ.get("EXTERNAL_LINKS", ">").split("|")) if k != ""
    }
    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME', 'http')
    APPLICATION_ROOT = os.environ.get('APPLICATION_ROOT', '/')
    SECRET_KEY = os.environ.get('SECRET_KEY')
    ADMIN_GROUP = os.environ.get('ADMIN_GROUP')

    # OIDC
    OIDC_CONFIGURATION_URL = os.environ.get('OIDC_CONFIGURATION_URL')
    OIDC_CLIENT_ID = os.environ.get('OIDC_CLIENT_ID')
    OIDC_CLIENT_SECRET = os.environ.get('OIDC_CLIENT_SECRET')
    OIDC_AUTHORIZE_URL = os.environ.get('OIDC_AUTHORIZE_URL')
    OIDC_TOKEN_URL = os.environ.get('OIDC_TOKEN_URL')
    OIDC_USERINFO_URL = os.environ.get('OIDC_USERINFO_URL')

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI') \
                              or 'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

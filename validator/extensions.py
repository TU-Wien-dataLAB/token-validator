from authlib.integrations.flask_client import OAuth
from flask_admin import Admin
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
admin = Admin(name='Admin', template_mode='bootstrap4')
oauth = OAuth()
migrate = Migrate(render_as_batch=True)

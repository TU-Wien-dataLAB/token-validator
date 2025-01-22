import logging
from secrets import token_hex

from flask import request, jsonify, render_template, redirect, url_for, current_app
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink

from validator.models import User, Token, Entity, TokenEntity
from validator.extensions import admin, db

log = logging.getLogger(__name__)


def random_token(nbytes=32) -> str:
    """Generate a random token."""
    return token_hex(nbytes=nbytes)


def update_user_token(user: User):
    if not user.token:
        user.token = Token()
    user.token.value = random_token()
    db.session.commit()


# Admin Views

class TokenValidatorAdminView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    can_edit = True
    page_size = 50

    def is_accessible(self):
        user = User.from_session()
        return False if user is None else user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('/', next=request.url))


class UserAdminView(TokenValidatorAdminView):
    column_list = ['id', 'email', 'is_admin', 'token.value']
    column_searchable_list = ['email', 'token.value']
    column_filters = ['is_admin']
    can_edit = False


class EntityAdminView(TokenValidatorAdminView):
    column_list = ['id', 'name', 'token.value']
    column_searchable_list = ['name', 'token.value']
    form_columns = ['name']
    # TODO: this should work but it does not
    #  possible solution: https://stackoverflow.com/questions/58403366/flask-admin-one-to-one-relationship-and-edit-form
    # inline_models = [(Token, dict(form_columns=('value',)))]


class TokenAdminView(TokenValidatorAdminView):
    column_list = ['id', 'token_entity.id', 'token_entity.type', 'value']
    column_searchable_list = ['value', 'token_entity.id', 'token_entity.type']
    form_columns = ['value']
    form_args = {"value": {"default": random_token}}


class TokenEntityAdminView(TokenValidatorAdminView):
    column_list = ['id', 'type', 'token_id']
    form_columns = ['id', 'type', 'token_id']


admin.add_view(UserAdminView(User, db.session))
admin.add_view(EntityAdminView(Entity, db.session))
admin.add_view(TokenAdminView(Token, db.session))
admin.add_view(TokenEntityAdminView(TokenEntity, db.session))
admin.add_link(MenuLink(name='UI', category='', url='/'))

# Routes

@current_app.route('/validate', methods=['GET', 'POST'])
def validate_token():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token_from_header = auth_header[7:]
        token_entry = Token.query.filter_by(value=token_from_header).first()
        if token_entry:
            return jsonify({'message': 'Token is valid'}), 200
        else:
            current_app.logger.info(f"Validate called with invalid token: {token_from_header}")
            return jsonify({'message': 'Token is invalid'}), 401
    else:
        return jsonify({'message': 'No Bearer token provided'}), 401


@current_app.route('/', methods=['GET'])
def token_page():
    """Display the current token on the page."""

    user: User | None = User.from_session()
    if user is None:
        return redirect(url_for('login'))
    return render_template('token.html', token=user.token.value, user=user, links=current_app.config.get('EXTERNAL_LINKS'))


@current_app.route('/regenerate-token', methods=['POST'])
def regenerate_token():
    """Generate a new token and update the database."""
    user: User | None = User.from_session()
    if user is None:
        return redirect(url_for('login'))
    update_user_token(user)
    return redirect(url_for('token_page'))

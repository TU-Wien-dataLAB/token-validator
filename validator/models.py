from typing import Self

from flask import session

from validator.extensions import db


class TokenEntity(db.Model):
    __tablename__ = 'token_entity'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    type = db.Column(db.String(32), nullable=False)
    token_id = db.Column(db.Integer, db.ForeignKey('token.id'), unique=True, nullable=True)
    token = db.relationship('Token', back_populates='token_entity', uselist=False)

    __mapper_args__ = {
        'polymorphic_on': type,
        "polymorphic_abstract": True
    }


class User(TokenEntity):
    __tablename__ = 'user'
    id = db.Column(db.ForeignKey("token_entity.id"), primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    __mapper_args__ = {
        'polymorphic_identity': 'user'
    }

    def __repr__(self):
        return f"User: {self.email} ({'Admin' if self.is_admin else 'User'})"

    @classmethod
    def from_session(cls) -> Self | None:
        uid = session.get('user_id')
        return None if uid is None else db.session.get(cls, uid)


class Entity(TokenEntity):
    __tablename__ = 'entity'
    id = db.Column(db.ForeignKey("token_entity.id"), primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)

    __mapper_args__ = {
        'polymorphic_identity': 'entity'
    }

    def __repr__(self):
        return f"Entity: {self.name}"


class Token(db.Model):
    __tablename__ = 'token'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    value = db.Column(db.String(255), unique=True, nullable=False)
    token_entity = db.relationship('TokenEntity', back_populates='token', uselist=False)

    def __repr__(self):
        return f"Token: {self.value}"

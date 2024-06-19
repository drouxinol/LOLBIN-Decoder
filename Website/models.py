#é aqui que vamos ter os modelos para a base de dados
from . import db
from flask_login import UserMixin


class Command(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Integer, nullable=False, unique=True)
    description = db.Column(db.String(5000))
    alias = db.Column(db.String)
    parameters = db.relationship('Parameter', backref='command', lazy=True) #vamos ter uma lista dos parametros associados a este comando

class Parameter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(5000), nullable=False)
    is_alone = db.Column(db.Boolean, nullable=False, default=True)
    command_id = db.Column(db.Integer, db.ForeignKey('command.id')) 

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True)
    password = db.Column(db.String(200))

class Validate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    command = db.Column(db.String(200), nullable=False)
    parameter = db.Column(db.String(200), nullable=False)
    param_description = db.Column(db.String(200)) 
    is_alone = db.Column(db.Boolean, nullable=False, default=True)


    

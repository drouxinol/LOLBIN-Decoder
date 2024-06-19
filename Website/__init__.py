import random
import string
import os
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from datetime import timedelta



def generate_key():
    lc_letters = string.ascii_lowercase
    uc_letters = string.ascii_uppercase
    punctuation = string.punctuation

    ans = []

    lc = [random.choice(lc_letters) for i in range(5)]
    uc = [random.choice(uc_letters) for i in range(5)]
    num = [str(random.randint(1, 99)) for i in range(5)]
    pun = [random.choice(punctuation) for i in range(5)]

    ans = lc + uc + num + pun
    random.shuffle(ans)

    return ''.join(ans)


db = SQLAlchemy() #criar o objeto - base de dados
DB_NAME = "data.db"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = generate_key()
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_NAME}" #registar a base de dados no flask

    # Set session timeout to 30 minutes
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
    db.init_app(app)

    from .views import views
    from .auth import auth
    from .models import User,Command,Parameter

    # Registar a blueprint das views na app
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    if not os.path.exists('instance/'+ DB_NAME):
         with app.app_context():
            db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    return app

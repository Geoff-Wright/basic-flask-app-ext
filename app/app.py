from flask import Flask
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager

from database.db import initialize_db

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'aSuperSecretKeyThatNobodyShouldBeAbleToGuess'
app.config['MONGODB_SETTINGS'] = 'mongodb://localhost/YOUR-DB-NAME'
app.config['JWT_TOKEN_LOCATION'] = 'cookies'

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

initialize_db(app)

from resources.routes import initialize_routes

initialize_routes(app)
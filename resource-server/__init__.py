# SPDX-License-Identifier: Apache-2.0 
# Copyright 2024 REDACTED FOR REVIEW
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_restful import Api
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials
from firebase_admin import messaging
from firebase_admin.exceptions import FirebaseError
from .config import CORS_ORIGINS, GOOGLE_CREDENTIAL_FILE_PATH
import logging
import os

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()
fcm = None
DB_PATH = ""
USER_FILES_PATH = ""
APEX_FILES_PATH = ""


def create_app():
    app = Flask(__name__)
    CORS(
        app,
        origins=CORS_ORIGINS,
        supports_credentials=True,
    )
    app.config["CORS_HEADERS"] = "Content-Type"
    app.config["SESSION_COOKIE_SAMESITE"] = "None"
    app.config["SESSION_COOKIE_SECURE"] = True

    app.config["SECRET_KEY"] = "xfuf2e+aTAWjBu6aAV9MG9SmqzmncO4zg5HGbW4k8bs="
    app.config["OAUTH2_REFRESH_TOKEN_GENERATOR"] = True
    logging.basicConfig(level=logging.DEBUG, filename="loginDEBUG.log", filemode="a")
    logging.getLogger("flask_cors").level = logging.DEBUG
    with app.app_context():
        DB_PATH = os.path.join(app.root_path, "data")
        global USER_FILES_PATH
        USER_FILES_PATH = os.path.join(app.root_path, "_user_files")

        if not os.path.exists(USER_FILES_PATH):
            os.makedirs(USER_FILES_PATH)
        global APEX_FILES_PATH
        APEX_FILES_PATH = os.path.join(app.root_path, "_apex_files")

        if not os.path.exists(APEX_FILES_PATH):
            os.makedirs(APEX_FILES_PATH)

        #google_credential = credentials.Certificate(GOOGLE_CREDENTIAL_FILE_PATH)
        #fcm = firebase_admin.initialize_app(google_credential)

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////" + DB_PATH + "/db.sqlite"

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))

    db.init_app(app)

    from .oauth import config_oauth

    config_oauth(app)
    from .oauth import oauth as oauth_blueprint

    app.register_blueprint(oauth_blueprint)

    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint

    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint

    app.register_blueprint(main_blueprint)

    # blueprint for non-auth parts of app
    from .apex import apex as apex_blueprint

    app.register_blueprint(apex_blueprint)

    from .api import api as api_blueprint
    from .api import Files, Wrapping, Profile, ProviderAgent, ProviderAgentSetup

    api = Api(api_blueprint)
    api.add_resource(
        Files,
        "/users/<user_id>/files/<path:unsafe_filename>",
        "/users/<user_id>/files/",
    )
    api.add_resource(
        Wrapping,
        "/users/<user_id>/wrapping/<path:unsafe_filename>",
        "/users/<user_id>/files/",
    )
    api.add_resource(Profile, "/users/")
    api.add_resource(ProviderAgent, "/users/<user_id>/provider-agent/")
    api.add_resource(ProviderAgentSetup, "/users/<user_id>/provider-agent-setup/")
    app.register_blueprint(api_blueprint, url_prefix="/api/v1")

    with app.app_context():
        if not os.path.exists(DB_PATH + "/_db.created"):
            print("Creating database")
            db.create_all()
            with open(DB_PATH + "/_db.created", "w") as fp:
                pass

    return app

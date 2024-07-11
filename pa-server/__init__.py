# SPDX-License-Identifier: Apache-2.0 
# Copyright 2024 REDACTED FOR REVIEW
from flask import Flask

def create_app():
    app = Flask(__name__)

    
    # blueprint for non-auth parts of app
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app


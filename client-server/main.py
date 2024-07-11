# SPDX-License-Identifier: Apache-2.0 
# Copyright 2024 REDACTED FOR REVIEW
from flask import Blueprint, render_template
from flask_login import login_required, current_user
main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@login_required
@main.route('/clientAgent')
def client_agent():
    return render_template('clientAgent.html',userId=current_user.id)

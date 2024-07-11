# SPDX-License-Identifier: Apache-2.0 
# Copyright 2024 REDACTED FOR REVIEW
from flask import Blueprint, render_template

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('load_pa.html')

@main.route('/provider-agent')
def provider_agent():
    return render_template('load_pa.html')

@main.route('/provider-agent/auth')
def apex_auth():
    return render_template('auth.html')


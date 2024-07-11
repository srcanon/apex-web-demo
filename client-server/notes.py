# SPDX-License-Identifier: Apache-2.0 
# Copyright 2024 REDACTED FOR REVIEW
from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
from flask import url_for, render_template, redirect
from flask import Blueprint, render_template
from flask_login import login_required, current_user

from requests.exceptions import HTTPError
from .oauth_client import oauth
from io import StringIO 
import json
notes = Blueprint('notes', __name__)

@notes.route('/notes/create', methods=['POST'])
@login_required
def create_note():
    data = request.json
    if "name" in data:
        empty_file = {"file": StringIO("{}")}
        resp = oauth.mydrive.post(str(current_user.oauth_uid) + '/files/NoteTaker/'+data["name"],files=empty_file)
        resp.raise_for_status()
        if resp.json()["success"] == True:
            return redirect(url_for("notes.get_notes"))        
    return "Error creating file", 500

@notes.route('/notes/list', methods=['GET'])
@login_required
def get_notes():
    
    notes = {}
    try:
        resp = oauth.mydrive.get(str(current_user.oauth_uid) + '/files/NoteTaker/')
        resp.raise_for_status()
        notes = resp.json()
    except HTTPError as err:
        if err.response.status_code == 404:
            resp = oauth.mydrive.post(str(current_user.oauth_uid) + '/files/NoteTaker/')
            resp.raise_for_status()
            if resp.json()["success"] == True:
                resp = oauth.mydrive.get(str(current_user.oauth_uid) + '/files/NoteTaker/')
                resp.raise_for_status()
                notes = resp.json()
                return jsonify(notes)
            return "Error creating directory", 500
        else:
            raise
    return jsonify(notes)

@notes.route('/notes/note', methods=['GET'])
@login_required
def get_note():
    
    
    if "name" in request.args:
        resp = oauth.mydrive.get(str(current_user.oauth_uid) + '/files/NoteTaker/'+request.args["name"])
        resp.raise_for_status()
        return jsonify(json.loads(resp.content))
    return "Error getting file", 500    

@notes.route('/notes/save', methods=['PUT'])
@login_required
def save_note():
    data = request.json
    if "name" in data and "data" in data:
        updated_file = {"file": StringIO(json.dumps(data["data"]))}
        resp = oauth.mydrive.put(str(current_user.oauth_uid) + '/files/NoteTaker/'+data["name"],files=updated_file)
        resp.raise_for_status()
        return jsonify(resp.json())
    return "Error updating file", 500
    


@notes.route('/notes')
@login_required
def index():
    return render_template('notes.html', name=current_user.name)

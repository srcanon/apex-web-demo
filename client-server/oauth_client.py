# SPDX-License-Identifier: Apache-2.0 
# Copyright 2024 REDACTED FOR REVIEW
from flask import url_for, redirect,jsonify
from flask import Blueprint
from flask_login import login_required, current_user
from . import db
from authlib.integrations.flask_client import OAuth
from .models import OAuth2Token, OTP
from .config import RESOURCE_PROFILE_URL, RESOURCE_API_URL
import secrets
import time
import hmac
oauth = OAuth()

def fetch_mydrive_token():
    token = OAuth2Token.query.filter_by(user_id=current_user.get_id()).first()
    return token.to_token()

def update_token(token, refresh_token=None, access_token=None):
    if refresh_token:
        item = OAuth2Token.query.filter_by(user_id=current_user.get_id(), refresh_token=refresh_token).first()
    elif access_token:
        item = OAuth2Token.query.filter_by(user_id=current_user.get_id(), access_token=access_token).first()
    else:
        return

    # update old token
    item.access_token = token['access_token']
    item.refresh_token = token.get('refresh_token')
    item.expires_at = token['expires_at']
    db.session.commit()


def config_oauth_client(app):
    oauth.init_app(app)
    oauth.register(name='mydrive', fetch_token=fetch_mydrive_token, update_token=update_token)


oauth_client = Blueprint('oauth_client', __name__)
CRS = "APEXNotesLink"
@oauth_client.route('/link')
@login_required
def link():
    generated_otp= str(secrets.randbelow(10000)).rjust(4, '0')
    encoded_otp = generated_otp.encode()
    hmac_obj = hmac.new(encoded_otp,CRS.encode(),"SHA512")
    otp_code = OTP(
        otp=generated_otp,
        user_id=current_user.get_id(),
        otp_time= int(time.time()),
        request_id=hmac_obj.hexdigest()
    )
    db.session.merge(otp_code)
    db.session.commit()
    resp = {"otp":generated_otp}
    return jsonify(resp)
    

@oauth_client.route('/link-authorise')
@login_required
def link_authorise():
    redirect_uri = url_for('oauth_client.authorize', _external=True)
    return oauth.mydrive.authorize_redirect(redirect_uri)



@oauth_client.route('/authorize')
@login_required
def authorize():
    token = oauth.mydrive.authorize_access_token()
    profile_resp = oauth.mydrive.get(RESOURCE_PROFILE_URL)
    profile_resp.raise_for_status()
    profile = profile_resp.json()
    newtoken = OAuth2Token(user_id=current_user.get_id(),token_type=token["token_type"],access_token=token["access_token"],expires_at=token["expires_at"],refresh_token=token["refresh_token"],scope=token["scope"],oauth_uid=profile["user_id"])
    db.session.merge(newtoken)
    current_user.is_linked = True
    current_user.oauth_uid = profile["user_id"]
    db.session.commit()
    return redirect('/notes')

@oauth_client.route('/test')
@login_required
def test():
    resp = oauth.mydrive.get(RESOURCE_API_URL)
    resp.raise_for_status()
    return redirect('/')
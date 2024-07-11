# SPDX-License-Identifier: Apache-2.0 
# Copyright 2024 REDACTED FOR REVIEW
from flask import (
    Blueprint,
    render_template,
    redirect,
    request,
    jsonify,
    abort,
)
from .models import Client, Token, User, AuthorizationCode, Device, DeviceAuth
from werkzeug.security import gen_salt
from flask import request, render_template
from authlib.integrations.flask_oauth2 import AuthorizationServer
from flask_login import login_required, current_user
from flask import stream_with_context, Response
from . import db
import secrets
import time
import json
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.integrations.flask_oauth2 import ResourceProtector, current_token

from authlib.oauth2.rfc6750 import BearerTokenValidator
from . import fcm
from firebase_admin import messaging



class MyBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        return Token.query.filter_by(access_token=token_string).first()


require_oauth = ResourceProtector()

# only bearer token is supported currently
require_oauth.register_token_validator(MyBearerTokenValidator())

oauth = Blueprint("oauth", __name__)


class RefreshTokenGrant(grants.RefreshTokenGrant):
    INCLUDE_NEW_REFRESH_TOKEN = True

    def authenticate_refresh_token(self, refresh_token):
        item = Token.query.filter_by(refresh_token=refresh_token).first()
        # define is_refresh_token_valid by yourself
        # usually, you should check if refresh token is expired and revoked
        if item and item.is_refresh_token_active():
            return item

    def authenticate_user(self, credential):
        return User.query.get(credential.user_id)

    def revoke_old_credential(self, credential):
        credential.revoked = True
        db.session.add(credential)
        db.session.commit()


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        client = request.client
        code_challenge = request.data.get("code_challenge")
        code_challenge_method = request.data.get("code_challenge_method")
        auth_code = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        item = AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id
        ).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)


# or with the helper
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
)

query_client = create_query_client_func(db.session, Client)
save_token = create_save_token_func(db.session, Token)
server = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def authenticate_user(self, username, password):
        user = User.query.filter_by(username=username).first()
        if user is not None and user.check_password(password):
            return user


def config_oauth(app):
    server.init_app(app)
    server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    server.register_grant(RefreshTokenGrant)


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


@oauth.route("/profile/")
@require_oauth()
def get_client_id():
    return jsonify({"user_id": current_token.user_id})


@oauth.route("/test/")
@require_oauth()
def test():
    return jsonify({"success": True})


@oauth.route("/developer/")
def index():
    if current_user:
        clients = Client.query.filter_by(user_id=current_user.get_id()).all()
    else:
        clients = []

    return render_template("dev-index.html", user=current_user, clients=clients)


@oauth.route("/developer/create_client", methods=("GET", "POST"))
@login_required
def create_client():
    user = current_user
    if not user:
        return redirect("/")
    if request.method == "GET":
        return render_template("create_client.html")

    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=user.id,
    )

    form = request.form
    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"],
    }
    client.set_client_metadata(client_metadata)

    if form["token_endpoint_auth_method"] == "none":
        client.client_secret = ""
    else:
        client.client_secret = gen_salt(48)

    client.pk_endpoint = form["pk_endpoint"]
    db.session.add(client)
    db.session.commit()
    return redirect("/developer")

@oauth.route("/oauth/authorize", methods=["GET", "POST"])
@login_required
def authorize():
    # Login is required since we need to know the current resource owner.
    # It can be done with a redirection to the login page, or a login
    # form on this authorization page.
    if request.method == "GET":
        is_apex = request.args.get("isAPEX", "")

        if request.headers.get("accept") == "text/event-stream":
            if is_apex == "True":
                grant = server.get_consent_grant(end_user=current_user)
                client = grant.client
                json_data = {"action": "authorize", "pk_endpoint": client.pk_endpoint}
                devices = Device.query.filter_by(user_id=current_user.get_id()).all()
                if len(devices) == 0:
                    return jsonify({"success": False, "msg": "No Devices Registered"})
                rand_id = secrets.token_urlsafe(48)
                dv_auth = DeviceAuth(
                    user_id=current_user.get_id(), one_time_url=rand_id, complete=0
                )
                db.session.add(dv_auth)
                db.session.commit()
                json_data["one_time_url"] = rand_id
                for device in devices:
                    registration_token = device.fcm_id
                    # Payload sent with high priority
                    message = messaging.Message(
                        data=json_data,
                        token=registration_token,
                        android=messaging.AndroidConfig(priority="high"),
                    )
                    # Send a message to the device corresponding to the provided
                    # registration token.
                    fcm_response = messaging.send(message)

                def generate(rand_id, user):
                    completed = False
                    while not completed:
                        check = DeviceAuth.query.filter_by(
                            user_id=user, one_time_url=rand_id, complete=1
                        ).first()
                        if check:
                            completed = True
                            data_to_send = (
                                "data:"
                                + json.dumps({"success": True, "msg": "PA Authorised"})
                                + "\n\n"
                            )
                            yield data_to_send
                        else:
                            data_to_send = (
                                "data:"
                                + json.dumps(
                                    {"success": False, "msg": "Awaiting Response"}
                                )
                                + "\n\n"
                            )
                            yield data_to_send
                            time.sleep(5)

                return Response(
                    stream_with_context(generate(rand_id, current_user.get_id())),
                    mimetype="text/event-stream",
                )
            else:
                abort(500, message="Non-APEX callers should not use the streaming API")
        else:
            if is_apex == "True":
                grant = server.get_consent_grant(end_user=current_user)
                client = grant.client
                devices = Device.query.filter_by(user_id=current_user.get_id()).all()
                json_data = {"action": "authorize", "pk_endpoint": client.pk_endpoint}
                if len(devices) == 0:
                    json_data["method"] = "Direct"
                else:
                    json_data["method"] = "Intermediary"

                return render_template(
                    "load_pa.html",
                    data=json.dumps(json_data),
                )

            else:
                grant = server.get_consent_grant(end_user=current_user)
                client = grant.client
                scope = client.get_allowed_scope(grant.request.scope)

                # You may add a function to extract scope into a list of scopes
                # with rich information, e.g.
                scopes = scope  # describe_scope(scope)  # returns [{'key': 'email', 'icon': '...'}]
                return render_template(
                    "authorize.html",
                    grant=grant,
                    user=current_user,
                    client=client,
                    scopes=scopes,
                )
    confirmed = request.form["confirm"]
    if confirmed:
        # granted by resource owner
        return server.create_authorization_response(grant_user=current_user)
    # denied by resource owner
    return server.create_authorization_response(grant_user=None)


@oauth.route("/oauth/token", methods=["POST"])
def issue_token():
    return server.create_token_response()


def query_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


def save_token(token_data, request):
    if request.user:
        user_id = request.user.get_user_id()
    else:
        # client_credentials grant_type
        user_id = request.client.user_id
        # or, depending on how you treat client_credentials
        user_id = None
    token = Token(client_id=request.client.client_id, user_id=user_id, **token_data)
    db.session.add(token)
    db.session.commit()

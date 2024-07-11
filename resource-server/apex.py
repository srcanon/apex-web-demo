# SPDX-License-Identifier: Apache-2.0 
# Copyright 2024 REDACTED FOR REVIEW
from flask import Blueprint, request, jsonify
from flask_login import current_user
from .models import Token
from functools import wraps
from types import NoneType
from authlib.integrations.flask_oauth2 import ResourceProtector, current_token
from authlib.oauth2.rfc6750 import BearerTokenValidator
from flask import stream_with_context, Response
import time
from flask import current_app, request, g
from flask_login.config import EXEMPT_METHODS
from . import USER_FILES_PATH, APEX_FILES_PATH
from . import db
import os
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicNumbers,
    SECP256R1,
)
import base64


class MyBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        return Token.query.filter_by(access_token=token_string).first()


require_oauth = ResourceProtector()

# only bearer token is supported currently
require_oauth.register_token_validator(MyBearerTokenValidator())


def validate_user(f):
    """
    This decorate ensures that the user logged in is the actually the same user we're operating on
    """

    @wraps(f)
    def func(*args, **kwargs):
        user_id = kwargs.get("user_id")
        if (
            not isinstance(current_token, NoneType)
            and user_id == str(current_token.user_id)
        ) or user_id == current_user.get_id():
            pass
        else:
            if user_id != current_user.get_id():
                raise Exception("Permission Error")
                # abort(404, message="You do not have permission to the resource you are trying to access")
        return f(*args, **kwargs)

    return func


def authenticate_user(scopes=None, optional=False):
    def inner_authenticate_user(f):
        """
        This decorate ensures that the user logged in is the actually the same user we're operating on
        """

        @wraps(f)
        def func(*args, **kwargs):
            if (
                current_user.is_authenticated
                or request.method in EXEMPT_METHODS
                or current_app.config.get("LOGIN_DISABLED")
            ):

                # flask 1.x compatibility
                # current_app.ensure_sync is only available in Flask >= 2.0
                if callable(getattr(current_app, "ensure_sync", None)):
                    return current_app.ensure_sync(f)(*args, **kwargs)
                return f(*args, **kwargs)
            else:
                deco = require_oauth(scopes, optional)(lambda: f(*args, **kwargs))
                return deco()

        return func

    return inner_authenticate_user


apex = Blueprint("apex", __name__)


# @login_required - removed to allow CA access
@apex.route("/promise")
def promise():
    # TODO ERROR HANDLING
    response = {}
    promise_id = request.args["promise_id"]

    promise_dir = os.path.join(APEX_FILES_PATH, promise_id)

    promise_file = os.path.join(promise_dir, "file")
    if os.path.exists(promise_file):
        with open(promise_file, "r") as f:
            response["promise_data"] = json.load(f)
    data_file = os.path.join(promise_dir, "data")
    promise_info = None
    with open(data_file, "r") as f:
        promise_info = json.load(f)
    if promise_info["type"] == "save":

        response["target_file"] = promise_info["target"]
        if os.path.exists(response["target_file"]):
            with open(response["target_file"], "r") as f:
                response["existing_data"] = json.load(f)
            response["existing_file"] = response["target_file"]
    elif promise_info["type"] == "rewrap":
        response["wrappedAgentKey"] = promise_info["wrappedAgentKey"]
        response["wrappedResourceKey"] = promise_info["wrappedResourceKey"]
        response["clientSignature"] = promise_info["clientSignature"]
        response["host"] = promise_info["host"]
    if "status" in promise_info:
        response["status"] = promise_info["status"]
    return jsonify(response)


@apex.route("/promise-ca")
def promise_ca():
    promise_id = request.args["promise_id"]

    def generate(promise_id):
        completed = False
        while not completed:
            response = {}
            promise_dir = os.path.join(APEX_FILES_PATH, promise_id)

            data_file = os.path.join(promise_dir, "data")
            with open(data_file, "r") as f:
                response = json.load(f)
            response["promiseId"] = promise_id
            data_to_send = "data:" + json.dumps(response) + "\n\n"
            yield data_to_send
            time.sleep(0.05)

    return Response(
        stream_with_context(generate(promise_id)), mimetype="text/event-stream"
    )


@apex.route("/promise-fulfilment", methods=("POST",))
def promise_fulfilment():
    # TODO ERROR HANDLING

    data = request.get_json()
    print(data)
    promise_id = data["promise_id"]
    server_promise_info = None
    promise_dir = os.path.join(APEX_FILES_PATH, promise_id)
    data_file = os.path.join(promise_dir, "data")
    with open(data_file, "r") as f:
        server_promise_info = json.load(f)

    type = ""

    if server_promise_info["type"] == "save":
        # Signature check
        # output["rSigBytes"]=rSigBytes;
        # output["rkSigBytes"]=rkSigBytes;
        re_encrypted_data = data["reEncryptedData"]
        wrapped_re_encryption_key = data["wrappedReEncKey"]
        promise_file = os.path.join(promise_dir, "file")
        target_file = server_promise_info["target"]
        type = "save"
        if not os.path.exists(target_file):
            type = "register"
        final_data = {}
        final_data["rSigBytes"] = data["rSigBytes"]
        final_data["rkSigBytes"] = data["rkSigBytes"]
        final_data["wrappedKey"] = wrapped_re_encryption_key
        final_data["encryptedData"] = re_encrypted_data
        with open(target_file, "w") as f:
            json.dump(final_data, f)
    elif server_promise_info["type"] == "rewrap":
        type = "rewrap"
        server_promise_info["reWrappedResourceKey"] = data["reWrappedResourceKey"]
    server_promise_info["status"] = "fulfilled"
    with open(data_file, "w") as f:
        json.dump(server_promise_info, f)

    final_response = {}
    final_response["promise_id"] = promise_id
    final_response["status"] = "fulfilled"
    final_response["type"] = type
    return jsonify(final_response)


def check_signature(public_key, dss_signature, data_string):
    curve = SECP256R1()
    try:
        public_key.verify(
            dss_signature, data_string.encode("utf-8"), ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        print("signature checking failed")
        return False


def convert_to_dss_sig(signature_bytes):
    return encode_dss_signature(
        int.from_bytes(signature_bytes[0:32], "big"),
        int.from_bytes(signature_bytes[32:], "big"),
    )


def convert_json_public_key(json_public_key):
    curve = SECP256R1()
    return (
        EllipticCurvePublicNumbers(
            int.from_bytes(
                base64.urlsafe_b64decode(json_public_key["x"] + "=="), "big"
            ),
            int.from_bytes(
                base64.urlsafe_b64decode(json_public_key["y"] + "=="), "big"
            ),
            curve,
        )
    ).public_key()

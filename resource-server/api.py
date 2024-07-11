# SPDX-License-Identifier: Apache-2.0 
# Copyright 2024 REDACTED FOR REVIEW
from types import NoneType
from flask import (
    Blueprint,
    request,
    send_file,
    jsonify,
)
from .models import (
    Token,
    ClientCertificate,
    DeviceAuth,
    Device,
)
from . import db
from . import USER_FILES_PATH, APEX_FILES_PATH
from flask import request, g
from flask_restful import reqparse, abort, Resource
from functools import wraps
from flask_login import current_user
from flask import current_app, request, g
from flask_restful import abort
from flask_login.config import EXEMPT_METHODS
from werkzeug.exceptions import HTTPException
from pathvalidate import sanitize_filepath
from werkzeug.datastructures import FileStorage
import json
import os
import uuid
from authlib.integrations.flask_oauth2 import ResourceProtector, current_token
from authlib.oauth2.rfc6750 import BearerTokenValidator
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicNumbers,
    SECP256R1,
)
from . import db
from .models import Device
import base64


from . import fcm
from firebase_admin import messaging


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
            # if user_id != current_user.get_id():
            abort(
                404,
                message="You do not have permission to the resource you are trying to access",
            )
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


api = Blueprint("api", __name__)


def path_to_dict(path):
    d = {"name": os.path.basename(path)}
    if os.path.isdir(path):
        d["type"] = "directory"
        d["children"] = [path_to_dict(os.path.join(path, x)) for x in os.listdir(path)]
    else:
        d["type"] = "file"
    return d


class Files(Resource):

    def _sanitize_path(self, filepath):
        return sanitize_filepath(filepath)

    def _validate_path(self, user_dir, filepath):
        return os.path.commonprefix([user_dir, os.path.realpath(filepath)])

    def _store_promise(self, target, file):
        final_data = {}
        final_data["target"] = target
        final_data["type"] = "save"
        promise_id = str(uuid.uuid4())
        promise_dir = os.path.join(APEX_FILES_PATH, promise_id)
        if not os.path.exists(promise_dir):
            os.makedirs(promise_dir)
        promise_file = os.path.join(promise_dir, "file")
        file.save(promise_file)
        data_file = os.path.join(promise_dir, "data")
        with open(data_file, "w") as f:
            json.dump(final_data, f)
        return promise_id

    @authenticate_user()
    @validate_user
    def get(self, user_id, unsafe_filename=None):
        try:
            if unsafe_filename is None:
                print("None filename")
            user_dir = os.path.join(USER_FILES_PATH, user_id)
            filepath = self._sanitize_path(unsafe_filename)
            if not self._validate_path(user_dir, filepath):
                raise Exception("Invalid path")

            target = os.path.join(user_dir, filepath)
            if not os.path.exists(user_dir):
                os.makedirs(user_dir)
            if os.path.exists(target):
                if os.path.isdir(target):
                    return path_to_dict(target)
                else:
                    return send_file(target)
            abort(404)
        except HTTPException as e1:
            raise
        except Exception as e:
            abort(
                500,
                message="There was an error while trying to get your files --> {}".format(
                    str(e)
                ),
            )

    @authenticate_user()
    @validate_user
    def post(self, user_id, unsafe_filename):
        try:
            user_dir = os.path.join(USER_FILES_PATH, user_id)
            filepath = self._sanitize_path(unsafe_filename)
            if not self._validate_path(user_dir, filepath):
                raise Exception("Invalid file path")

            target = os.path.join(user_dir, filepath)
            parser = reqparse.RequestParser()
            if os.path.exists(target):
                return "Path already exists, use PUT instead of POST", 400
            parser.add_argument(
                "file", type=FileStorage, location="files", default=None
            )
            parser.add_argument("type", location="args")
            args = parser.parse_args()
            if not args["file"] is None:
                if "type" in args and args["type"] == "APEX":
                    file = args["file"]
                    json_file = json.loads(file.read())
                    file.seek(0)
                    name = unsafe_filename.replace("NoteTaker/", "", 1)
                    # signature_data = str(user_id) + name + json_file["wrappedKey"] + json.dumps(json_file["encryptedData"])
                    # client_certificate = ClientCertificate.query.filter_by(user_id=user_id, host=json_file["host"]).first()
                    # public_signing_key = convert_json_public_key(json.loads(client_certificate.public_key))
                    # dss_signature = base64.urlsafe_b64decode(json_file["clientSignature"])

                    # public_signing_key.verify(dss_signature,signature_data.encode('utf-8'),ec.ECDSA(hashes.SHA256()))

                    promise_id = self._store_promise(target, file=args["file"])

                    devices = Device.query.filter_by(user_id=user_id).all()
                    resp_data = {}
                    resp_data["success"] = True
                    resp_data["promise_id"] = promise_id

                    if len(devices) == 0:
                        resp_data["promise"] = "direct"
                    else:
                        resp_data["promised"] = "indirect"
                        fcm_data = {}
                        fcm_data["promise_id"] = promise_id
                        fcm_data["action"] = "save"
                        for device in devices:
                            registration_token = device.fcm_id
                            # Payload sent with high priority
                            message = messaging.Message(
                                data=fcm_data,
                                token=registration_token,
                                android=messaging.AndroidConfig(priority="high"),
                            )
                            # Send a message to the device corresponding to the provided
                            # registration token.
                            fcm_response = messaging.send(message)
                    return jsonify(resp_data)
                else:
                    file = args["file"]
                    file.save(target)
                    return jsonify({"success": True})
            else:
                os.mkdir(target)
                return jsonify({"success": True})
        except InvalidSignature:
            print("signature checking failed", flush=True)
            abort(
                500,
                message="Signature checking failed --> {}".format(e),
            )
        except Exception as e:
            print(e)
            traceback.print_exc()
            abort(
                500,
                message="There was an error while processing your request --> {}".format(
                    e
                ),
            )

    @authenticate_user()
    @validate_user
    def put(self, user_id, unsafe_filename):
        try:
            user_dir = os.path.join(USER_FILES_PATH, user_id)
            filepath = self._sanitize_path(unsafe_filename)
            if not self._validate_path(user_dir, filepath):
                raise Exception("Invalid file path")

            target = os.path.join(user_dir, filepath)
            parser = reqparse.RequestParser()

            if not os.path.exists(target):
                abort(404, "Path does not exist, use POST instead of PUT")

            if target.endswith("/"):
                abort(400, "Cannot edit folders")

            # Must be a file
            parser.add_argument("file", type=FileStorage, location="files")

            parser.add_argument("type", location="args")
            args = parser.parse_args()
            if "type" in args and args["type"] == "APEX":
                promise_id = self._store_promise(target, file=args["file"])
                devices = Device.query.filter_by(user_id=user_id).all()
                resp_data = {}
                resp_data["success"] = True
                resp_data["promise_id"] = promise_id

                if len(devices) == 0:
                    resp_data["promise"] = "direct"
                else:
                    resp_data["promise"] = "indirect"
                    fcm_data = {}
                    fcm_data["promise_id"] = promise_id
                    fcm_data["action"] = "save"
                    for device in devices:
                        registration_token = device.fcm_id
                        # Payload sent with high priority
                        message = messaging.Message(
                            data=fcm_data,
                            token=registration_token,
                            android=messaging.AndroidConfig(priority="high"),
                        )
                        # Send a message to the device corresponding to the provided
                        # registration token.
                        fcm_response = messaging.send(message)
                return jsonify(resp_data)

                # SEND TO PA
                # return jsonify({"success":True,"promise_id":promise_id,"promise":"direct"})
            else:

                file = args["file"]
                file.save(target)
                return jsonify({"success": True})
        except InvalidSignature:
            print("signature checking failed", flush=True)
            abort(
                500,
                message="Signature checking failed --> {}".format(e),
            )
        except Exception as e:
            print(e)
            abort(
                500,
                message="There was an error while processing your request --> {}".format(
                    e
                ),
            )

    @authenticate_user()
    @validate_user
    def delete(self, user_id, unsafe_filename):
        try:
            user_dir = os.path.join(USER_FILES_PATH, user_id)
            filepath = self._sanitize_path(unsafe_filename)
            if not self._validate_path(user_dir, filepath):
                raise Exception("Invalid file path")

            target = os.path.join(user_dir, filepath)
            parser = reqparse.RequestParser()

            if not os.path.exists(target):
                abort(404, "Path does not exist")

            if target.endswith("/"):
                os.rmdir(target)
            else:
                os.remove(target)

            return jsonify({"success": True})
        except Exception as e:
            print(e)
            abort(
                500,
                message="There was an error while processing your request --> {}".format(
                    e
                ),
            )


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


class Wrapping(Resource):

    def _sanitize_path(self, filepath):
        return sanitize_filepath(filepath)

    def _validate_path(self, user_dir, filepath):
        return os.path.commonprefix([user_dir, os.path.realpath(filepath)])

    def _store_promise(
        self, target, wrapped_agent_key, wrapped_resource_key, clientSignature, host
    ):
        final_data = {}
        final_data["target"] = target
        final_data["type"] = "rewrap"
        final_data["host"] = host
        final_data["wrappedAgentKey"] = wrapped_agent_key
        final_data["wrappedResourceKey"] = wrapped_resource_key
        final_data["clientSignature"] = clientSignature

        promise_id = str(uuid.uuid4())
        promise_dir = os.path.join(APEX_FILES_PATH, promise_id)
        if not os.path.exists(promise_dir):
            os.makedirs(promise_dir)
        data_file = os.path.join(promise_dir, "data")
        with open(data_file, "w") as f:
            json.dump(final_data, f)
        return promise_id

    @authenticate_user()
    @validate_user
    def post(self, user_id, unsafe_filename):
        try:
            user_dir = os.path.join(USER_FILES_PATH, user_id)
            filepath = self._sanitize_path(unsafe_filename)
            if not self._validate_path(user_dir, filepath):
                raise Exception("Invalid file path")

            target = os.path.join(user_dir, filepath)
            parser = reqparse.RequestParser()
            parser.add_argument("wrappedAgentKey", type=str, location="json")
            parser.add_argument("wrappedKey", type=str, location="json")
            parser.add_argument("clientSignature", type=str, location="json")
            parser.add_argument("host", type=str, location="json")

            args = parser.parse_args()

            if (
                not args["wrappedAgentKey"] is None
                and not args["wrappedAgentKey"] is None
            ):

                wrapped_agent_key = args["wrappedAgentKey"]
                wrapped_resource_key = args["wrappedKey"]
                promise_id = self._store_promise(
                    target,
                    wrapped_agent_key,
                    wrapped_resource_key,
                    args["clientSignature"],
                    args["host"],
                )

                devices = Device.query.filter_by(user_id=user_id).all()
                resp_data = {}
                resp_data["success"] = True
                resp_data["promise_id"] = promise_id

                if len(devices) == 0:
                    resp_data["promise"] = "direct"
                else:
                    resp_data["promised"] = "indirect"
                    fcm_data = {}
                    fcm_data["promise_id"] = promise_id
                    fcm_data["action"] = "retrieve"
                    for device in devices:
                        registration_token = device.fcm_id
                        # Payload sent with high priority
                        message = messaging.Message(
                            data=fcm_data,
                            token=registration_token,
                            android=messaging.AndroidConfig(priority="high"),
                        )
                        # Send a message to the device corresponding to the provided
                        # registration token.
                        fcm_response = messaging.send(message)
                return jsonify(resp_data)
        except Exception as e:
            print(e)
            abort(
                500,
                message="There was an error while processing your request --> {}".format(
                    e
                ),
            )


class Profile(Resource):

    @authenticate_user()
    def get(self):
        try:
            return jsonify({"success": True})
        except Exception as e:
            print(e)
            abort(
                500,
                message="There was an error while processing your request --> {}".format(
                    e
                ),
            )


class ProviderAgent(Resource):

    @authenticate_user()
    @validate_user
    def get(self, user_id):
        try:
            return jsonify({"success": True})
        except Exception as e:
            print(e)
            abort(
                500,
                message="There was an error while processing your request --> {}".format(
                    e
                ),
            )

    def send_to_fcm(self, target, msg: dict):
        """Internal function to send a message via Firebase
        Cloud Messaging

        Args:
            target (str): target FCM device ID
            msg (dict): JSON message to send
        """
        # This registration token comes from the client FCM SDKs.
        registration_token = target

        # Payload sent with high priority
        message = messaging.Message(
            data=msg,
            token=registration_token,
            android=messaging.AndroidConfig(priority="high"),
        )

        # Send a message to the device corresponding to the provided
        # registration token.
        response = messaging.send(message)

    @authenticate_user()
    @validate_user
    def put(self, user_id):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument("fcmID", type=str, location="json")
            parser.add_argument("deviceID", type=str, location="json")
            args = parser.parse_args()
            if not args["fcmID"] is None and not args["deviceID"] is None:
                newDevice = Device(
                    user_id=user_id, device_id=args["deviceID"], fcm_id=args["fcmID"]
                )
                qry_object = db.session.query(Device).where(
                    Device.device_id == newDevice.device_id,
                    Device.user_id == newDevice.user_id,
                )
                if qry_object.first() is None:
                    db.session.add(newDevice)
                else:
                    qry_object.update({"fcm_id": args["fcmID"]})
                db.session.commit()
                test = {}
                test["message"] = "This is a test"
                self.send_to_fcm(args["fcmID"], test)
                return jsonify({"success": True})
            return jsonify({"success": False})
        except Exception as e:
            print(e)
            abort(
                500,
                message="There was an error while processing your request --> {}".format(
                    e
                ),
            )


class ProviderAgentSetup(Resource):

    @authenticate_user()
    @validate_user
    def post(self, user_id):
        try:
            # TODO add checks that parameters are there
            parser = reqparse.RequestParser()
            parser.add_argument("hostname", type=str, location="json")
            parser.add_argument("signature", type=str, location="json")
            parser.add_argument("clientPublicKey", type=dict, location="json")
            args = parser.parse_args()
            client_cert = ClientCertificate(
                user_id=user_id,
                public_key=json.dumps(args["clientPublicKey"]),
                pk_signature=json.dumps(args["signature"]),
                host=args["hostname"],
            )
            db.session.add(client_cert)
            db.session.commit()
            return jsonify({"success": True})
        except Exception as e:
            print(e)
            abort(
                500,
                message="There was an error while processing your request --> {}".format(
                    e
                ),
            )

    @authenticate_user()
    @validate_user
    def put(self, user_id):
        parser = reqparse.RequestParser()
        parser.add_argument("uid", type=str, location="json")
        data = parser.parse_args()
        if "uid" in data:
            rand_id = data["uid"]
            device_auth = DeviceAuth.query.filter_by(
                user_id=user_id, one_time_url=rand_id, complete=0
            ).first()
            if device_auth:
                device_auth.complete = 1
                db.session.commit()
                return jsonify({"success": True})
            abort(500, message="URL Incorrect or Timed Out")
        abort(500, message="Missing parameters")

# SPDX-License-Identifier: Apache-2.0 
# Copyright 2024 REDACTED FOR REVIEW
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, ClientCertificate
from flask_login import login_user, login_required, logout_user, current_user

# from werkzeug.urls import url_quote
import urllib.parse
from . import db
import json

auth = Blueprint("auth", __name__)


@auth.route("/client_cert_endpoint", methods=["POST"])
@login_required
def client_cert_endpoint():
    data = request.json
    client_cert = ClientCertificate(
        user_id=current_user.get_id(),
        public_key=json.dumps(data["clientPublicKey"]),
        pk_signature=json.dumps(data["signature"]),
        host=data["hostname"],
    )
    db.session.add(client_cert)
    db.session.commit()
    return jsonify({"success": True})


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))


@auth.route("/login")
def login():
    next = request.args.get("next", default="", type=str)
    return render_template("login.html", next=urllib.parse.quote_plus(next))


@auth.route("/login", methods=["POST"])
def login_post():
    email = request.form.get("email")
    password = request.form.get("password")
    remember = True if request.form.get("remember") else False
    next = request.args.get("next", default="", type=str)
    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash("Please check your login details and try again.")
        return redirect(
            url_for("auth.login")
        )  # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    if next != "":
        return redirect(next)
    else:
        return redirect(url_for("main.profile"))


@auth.route("/signup")
def signup():
    return render_template("signup.html")


@auth.route("/signup", methods=["POST"])
def signup_post():
    # code to validate and add user to database goes here
    email = request.form.get("email")
    name = request.form.get("name")
    password = request.form.get("password")

    user = User.query.filter_by(
        email=email
    ).first()  # if this returns a user, then the email already exists in database

    if (
        user
    ):  # if a user is found, we want to redirect back to signup page so user can try again
        flash("Email address already exists")
        return redirect(url_for("auth.signup"))

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(email=email, name=name, password=generate_password_hash(password))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for("auth.login"))

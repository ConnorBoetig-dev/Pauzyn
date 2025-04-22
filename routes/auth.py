# ------------------- IMPORTS AND DEPENDENCIES ---------------------------
import logging                                      # std‑lib logging for debug/info
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, current_app  # Flask helpers
import os                                           # env‑var access
import hmac, hashlib, base64                        # build Cognito SECRET_HASH
import json, uuid                                   # misc utilities (uuid unused here)
from datetime import datetime                       # timestamps (currently unused)

import boto3                                        # AWS SDK (talks to Cognito)
from botocore.exceptions import ClientError         # typed AWS errors (unused directly)
import requests                                     # generic HTTP client (unused here)
import jwt                                          # decode JWTs (Cognito id_token)

# ------------------- INITIAL SETUP ---------------------------
logging.basicConfig(level=logging.DEBUG)            # set global log level
logger = logging.getLogger(__name__)                # module‑scoped logger instance

auth_bp = Blueprint('auth', __name__)               # /auth blueprint definition

# ----- Cognito configuration pulled from .env -----
USER_POOL_ID  = os.getenv('COGNITO_USER_POOL_ID')   # user pool ID from env
CLIENT_ID     = os.getenv('COGNITO_CLIENT_ID')      # app client ID from env
CLIENT_SECRET = os.getenv('COGNITO_CLIENT_SECRET')  # app client secret
REGION        = os.getenv('AWS_REGION')             # AWS region name

client = boto3.client('cognito-idp', region_name=REGION)  # boto3 Cognito client

# ------------------- AUTHENTICATION ROUTES ---------------------------
@auth_bp.route('/login', methods=['GET', 'POST'])    # /auth/login endpoint
def login():
    """Custom login using Cognito USER_PASSWORD_AUTH flow."""
    if request.method == 'POST':                     # form submitted?
        email    = request.form['email']             # get email field
        password = request.form['password']          # get password field
        try:
            secret_hash = get_secret_hash(email)     # compute SECRET_HASH for app client
            resp = client.initiate_auth(             # call Cognito to authenticate
                ClientId=CLIENT_ID,                  # cognito app client id
                AuthFlow='USER_PASSWORD_AUTH',       # choose username/password flow
                AuthParameters={                     # parameters required
                    'USERNAME': email,               # username (email)
                    'PASSWORD': password,            # plaintext password
                    'SECRET_HASH': secret_hash       # HMAC‑based secret hash
                }
            )
            auth = resp['AuthenticationResult']      # token bundle from Cognito
            session['access_token']  = auth['AccessToken']   # short‑lived API token
            session['id_token']      = auth['IdToken']       # JWT with user claims
            session['refresh_token'] = auth['RefreshToken']  # token for renewal
            decoded = jwt.decode(auth['IdToken'], options={"verify_signature": False})  # decode JWT w/o verify
            session['user_name'] = decoded.get('name', 'User')  # grab display name
            flash('Login successful!', 'success')    # UX: green toast message
            return redirect(url_for('home'))         # go to homepage
        except client.exceptions.NotAuthorizedException:      # bad creds
            flash('Incorrect username or password', 'danger') # red toast
        except client.exceptions.UserNotConfirmedException:   # needs email verify
            flash('Please confirm your account via email.', 'warning')
        except client.exceptions.UserNotFoundException:       # no such user
            flash('Incorrect username or password', 'danger')
        except client.exceptions.InvalidParameterException:   # malformed request
            flash('Invalid login parameters.', 'danger')
        except Exception as e:                       # anything else
            logger.error(f"Login error: {e}", exc_info=True)  # log stacktrace
            flash('Unexpected error. Try again.', 'danger')
    return render_template('auth/login.html')        # GET or failed POST -> show form

# ------------------- COGNITO HASH UTILITY ---------------------------
def get_secret_hash(username: str) -> str:           # generate HMAC‑SHA256 secret hash
    msg = username + CLIENT_ID                       # per Cognito spec
    dig = hmac.new(CLIENT_SECRET.encode(),           # key = client secret
                   msg.encode(),                     # message bytes
                   hashlib.sha256).digest()          # hash → raw bytes
    return base64.b64encode(dig).decode()            # base64‑string for API

# ------------------- REGISTRATION ROUTES ---------------------------
@auth_bp.route('/signup', methods=['GET', 'POST'])   # /auth/signup endpoint
def signup():
    """Register new user via Cognito sign_up."""
    if request.method == 'POST':                     # form submitted?
        email    = request.form['email']             # collect fields
        password = request.form['password']
        confirm  = request.form['confirmPassword']
        name     = request.form['name']

        if password != confirm:                      # simple validation
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('auth.signup'))
        try:
            response = client.sign_up(               # Cognito sign‑up API
                ClientId=CLIENT_ID,
                Username=email,
                Password=password,
                SecretHash=get_secret_hash(email),
                UserAttributes=[
                    {'Name': 'name', 'Value': name},
                    {'Name': 'email', 'Value': email},
                    {'Name': 'preferred_username', 'Value': email}
                ]
            )
            user_id = response['UserSub']            # Cognito GUID for user
            if current_app.db_manager.create_user(user_id, email, name):  # add to DynamoDB
                session['temp_email'] = email        # store for confirm step
                flash('Check your email for a code.', 'success')
                return redirect(url_for('auth.confirm'))
            else:
                logger.error(f"Failed to create DynamoDB record for user: {email}")
                flash('Account created but profile setup failed. Please contact support.', 'warning')
                return redirect(url_for('auth.confirm'))
        except client.exceptions.UsernameExistsException:
            flash('Email already registered.', 'danger')
        except client.exceptions.InvalidPasswordException:
            flash('Password fails complexity rules.', 'danger')
        except Exception as e:
            logger.error(f"Signup error: {e}", exc_info=True)
            flash('Registration failed.', 'danger')
    return render_template('auth/signup.html')       # show form

# ------------------- EMAIL VERIFICATION ROUTES ---------------------------
@auth_bp.route('/confirm', methods=['GET', 'POST'])  # /auth/confirm endpoint
def confirm():
    """Verify email with the code Cognito emailed."""
    if 'temp_email' not in session:                 # guard: came from signup?
        flash('Please sign up first.', 'warning')   # notify
        return redirect(url_for('auth.signup'))     # back to signup
    if request.method == 'POST':                    # code submitted
        code  = request.form['code']                # 6‑digit code
        email = session['temp_email']               # email from signup
        try:
            client.confirm_sign_up(                 # Cognito confirm API
                ClientId=CLIENT_ID,
                Username=email,
                ConfirmationCode=code,
                SecretHash=get_secret_hash(email)
            )
            session.pop('temp_email', None)         # cleanup temp email
            flash('Email verified! You can now log in.', 'success')
            return redirect(url_for('auth.login'))  # onward to login
        except client.exceptions.CodeMismatchException:
            flash('Invalid code.', 'danger')
        except client.exceptions.ExpiredCodeException:
            flash('Code expired.', 'danger')
        except Exception as e:
            logger.error(f"Confirm error: {e}", exc_info=True)
            flash('Verification failed.', 'danger')
    return render_template('auth/confirm.html')     # GET or failed POST

# ------------------- SESSION MANAGEMENT ROUTES ---------------------------
@auth_bp.route('/logout')                           # /auth/logout endpoint
def logout():
    """Clear session and log out user."""
    for k in ('access_token', 'id_token', 'refresh_token', 'user_name'):  # keys to drop
        session.pop(k, None)                        # remove if present
    session.clear()                                 # extra safety
    flash('Logged out.', 'success')                 # UX feedback
    return redirect(url_for('home'))                # back to home

# ------------------- VERIFICATION SUPPORT ROUTES ---------------------------
@auth_bp.route('/resend-code')                      # /auth/resend-code endpoint
def resend_code():
    """Send a new verification code email."""
    if 'temp_email' not in session:                 # need pending email
        flash('Please sign up first.', 'warning')
        return redirect(url_for('auth.signup'))
    try:
        email = session['temp_email']               # pull stored email
        client.resend_confirmation_code(            # Cognito API
            ClientId=CLIENT_ID,
            Username=email,
            SecretHash=get_secret_hash(email)
        )
        flash('Code re‑sent.', 'success')           # success toast
    except Exception as e:
        logger.error(f"Resend code error: {e}", exc_info=True)
        flash('Could not resend code.', 'danger')   # error toast
    return redirect(url_for('auth.confirm'))        # back to confirm page

# ------------------- TOKEN UTILITIES ---------------------------
def is_token_valid() -> bool:                       # quick presence check for tokens
    return 'access_token' in session and 'id_token' in session

def refresh_tokens() -> bool:                       # try to refresh expired tokens
    if 'refresh_token' not in session:              # missing refresh token
        return False
    try:
        resp = client.initiate_auth(                # Cognito refresh flow
            ClientId=CLIENT_ID,
            AuthFlow='REFRESH_TOKEN_AUTH',
            AuthParameters={'REFRESH_TOKEN': session['refresh_token']}
        )
        auth = resp['AuthenticationResult']         # new tokens
        session['access_token'] = auth['AccessToken']
        session['id_token']    = auth['IdToken']
        return True
    except Exception as e:
        logger.error(f"Token refresh error: {e}", exc_info=True)
        return False

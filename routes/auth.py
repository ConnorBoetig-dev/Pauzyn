import logging                                      # std‑lib logging for debug/info
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, current_app  # Flask helpers
import os                                           # env‑var access
import hmac, hashlib, base64                        # build Cognito SECRET_HASH
import json, uuid                                   # misc utilities (uuid unused here)
from datetime import datetime                       # timestamps (currently unused)

import boto3                                        # AWS SDK
from botocore.exceptions import ClientError         # typed AWS errors
import requests                                     # generic HTTP client (unused here)
import jwt                                          # decode JWTs (Cognito id_token)

# ------------------- INITIAL SETUP ---------------------------
# Sets up logging, blueprint, and AWS Cognito client configuration

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)               # /auth blueprint definition

# ----- Cognito configuration pulled from .env -----
USER_POOL_ID  = os.getenv('COGNITO_USER_POOL_ID')   # pool id
CLIENT_ID     = os.getenv('COGNITO_CLIENT_ID')      # app client id
CLIENT_SECRET = os.getenv('COGNITO_CLIENT_SECRET')  # app client secret
REGION        = os.getenv('AWS_REGION')             # AWS region

client = boto3.client('cognito-idp', region_name=REGION)  # AWS Cognito API client

# ------------------- AUTHENTICATION ROUTES ---------------------------
# Core authentication endpoints for user login. Handles username/password verification
# and manages session tokens received from Cognito.

@auth_bp.route('/login', methods=['GET', 'POST'])    # /auth/login endpoint definition
def login():
    """Custom login -> Cognito USER_PASSWORD_AUTH flow."""
    if request.method == 'POST':                     # handle form submission
        email    = request.form['email']             # extract email from form data
        password = request.form['password']          # extract password from form data
        try:
            secret_hash = get_secret_hash(email)     # generate hash required by Cognito for app client
            resp = client.initiate_auth(             # start Cognito authentication flow
                ClientId=CLIENT_ID,                  # app client identifier
                AuthFlow='USER_PASSWORD_AUTH',       # use username/password auth flow
                AuthParameters={                     # required auth parameters
                    'USERNAME': email,               # user's email as username
                    'PASSWORD': password,            # user's password
                    'SECRET_HASH': secret_hash       # computed hash for security
                }
            )
            auth = resp['AuthenticationResult']      # extract auth data from response
            session['access_token']  = auth['AccessToken']   # store token for API calls
            session['id_token']      = auth['IdToken']       # store JWT for user info
            session['refresh_token'] = auth['RefreshToken']  # store token for renewal
            decoded = jwt.decode(auth['IdToken'], options={"verify_signature": False})  # parse JWT payload
            session['user_name'] = decoded.get('name', 'User')  # extract user name from token
            flash('Login successful!', 'success')    # show success message
            return redirect(url_for('home'))         # redirect to home page
        except client.exceptions.NotAuthorizedException:     # wrong credentials
            flash('Incorrect username or password', 'danger')
        except client.exceptions.UserNotConfirmedException:  # email not verified
            flash('Please confirm your account via email.', 'warning')
        except client.exceptions.UserNotFoundException:      # user doesn't exist
            flash('Incorrect username or password', 'danger')
        except client.exceptions.InvalidParameterException:  # malformed request
            flash('Invalid login parameters.', 'danger')
        except Exception as e:                       # catch-all for other errors
            logger.error(f"Login error: {e}", exc_info=True)  # log unexpected errors
            flash('Unexpected error. Try again.', 'danger')
    return render_template('auth/login.html')        # show login form for GET/failed POST

# ------------------- COGNITO HASH UTILITY ---------------------------
# Generates the secret hash required by Cognito for app client authentication.
# This is required for all Cognito API calls when using an app client with a secret.

def get_secret_hash(username: str) -> str:           # helper function to generate Cognito hash
    msg = username + CLIENT_ID                       # combine username and client ID as required by Cognito
    dig = hmac.new(CLIENT_SECRET.encode(),          # create new HMAC using client secret as key
                   msg.encode(),                     # encode message to bytes
                   hashlib.sha256).digest()          # use SHA256 algorithm and get raw bytes
    return base64.b64encode(dig).decode()           # convert bytes to base64 then to string for Cognito

# ------------------- REGISTRATION ROUTES ---------------------------
# Handles new user registration flow, including initial signup, email verification,
# and code confirmation. Works with Cognito's built-in verification system.

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """Register new user via Cognito sign_up."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirmPassword']
        name = request.form['name']
        
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('auth.signup'))
            
        try:
            # Cognito signup
            response = client.sign_up(
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
            
            # Create DynamoDB user record
            user_id = response['UserSub']  # Get the Cognito user ID
            if current_app.db_manager.create_user(user_id, email, name):
                session['temp_email'] = email
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
            
    return render_template('auth/signup.html')       # show signup form for GET/failed POST

# ------------------- EMAIL VERIFICATION ROUTES ---------------------------
# Manages the email verification process after signup, including code confirmation
# and code resending functionality.

@auth_bp.route('/confirm', methods=['GET', 'POST'])  # /auth/confirm endpoint definition
def confirm():
    """Verify email with the code Cognito emailed."""
    if 'temp_email' not in session:                 # check if user came from signup
        flash('Please sign up first.', 'warning')   # show warning message
        return redirect(url_for('auth.signup'))     # redirect to signup page if no email in session
    if request.method == 'POST':                    # handle confirmation code submission
        code  = request.form['code']                # get verification code from form
        email = session['temp_email']               # get stored email from signup
        try:
            client.confirm_sign_up(                 # call Cognito confirmation API
                ClientId=CLIENT_ID,                 # app client identifier
                Username=email,                     # email used during signup
                ConfirmationCode=code,             # code user entered from email
                SecretHash=get_secret_hash(email)  # required hash for app client auth
            )
            session.pop('temp_email', None)        # remove temporary email from session
            flash('Email verified! You can now log in.', 'success')  # show success message
            return redirect(url_for('auth.login'))  # send user to login page
        except client.exceptions.CodeMismatchException:    # wrong verification code
            flash('Invalid code.', 'danger')              # show error message
        except client.exceptions.ExpiredCodeException:     # code has expired
            flash('Code expired.', 'danger')              # show error message
        except Exception as e:                            # catch any other errors
            logger.error(f"Confirm error: {e}", exc_info=True)  # log the error
            flash('Verification failed.', 'danger')       # show generic error message
    return render_template('auth/confirm.html')     # show confirmation page for GET/failed POST

# ------------------- SESSION MANAGEMENT ROUTES ---------------------------
# Handles user logout and session cleanup, ensuring secure termination of user sessions
# and proper removal of authentication tokens.

@auth_bp.route('/logout')                           # /auth/logout endpoint definition
def logout():
    """Clear session and log out user."""
    for k in ('access_token', 'id_token', 'refresh_token', 'user_name'):  # list of session keys to remove
        session.pop(k, None)                        # remove each token key safely (None if not found)
    session.clear()                                 # clear entire session for extra security
    flash('Logged out.', 'success')                 # show success message to user
    return redirect(url_for('home'))                # redirect user to home page

# ------------------- VERIFICATION SUPPORT ROUTES ---------------------------
# Provides support functionality for the verification process, such as resending
# verification codes when they expire or are lost.

@auth_bp.route('/resend-code')                      # /auth/resend-code endpoint definition
def resend_code():
    """Send a new verification code email."""
    if 'temp_email' not in session:                 # check if user has a pending verification
        flash('Please sign up first.', 'warning')   # show warning if no email in session
        return redirect(url_for('auth.signup'))     # redirect to signup page
    try:
        email = session['temp_email']               # get stored email from signup process
        client.resend_confirmation_code(            # call Cognito API to resend code
            ClientId=CLIENT_ID,                     # app client identifier
            Username=email,                         # email used during signup
            SecretHash=get_secret_hash(email)       # required hash for app client auth
        )
        flash('Code re‑sent.', 'success')          # show success message to user
    except Exception as e:                          # catch any Cognito API errors
        logger.error(f"Resend code error: {e}", exc_info=True)  # log the error details
        flash('Could not resend code.', 'danger')   # show error message to user
    return redirect(url_for('auth.confirm'))        # return to confirmation page

# ------------------- TOKEN UTILITIES ---------------------------
# Helper functions for managing Cognito tokens, including validation and refresh
# functionality. These utilities support maintaining active sessions and handling
# token expiration.

def is_token_valid() -> bool:                       # helper function to check token presence
    return 'access_token' in session and 'id_token' in session  # verify both required tokens exist

def refresh_tokens() -> bool:                       # helper function to refresh expired tokens
    if 'refresh_token' not in session:              # check if refresh token exists
        return False                                # can't refresh without refresh token
    try:
        resp = client.initiate_auth(                # call Cognito auth API
            ClientId=CLIENT_ID,                     # app client identifier
            AuthFlow='REFRESH_TOKEN_AUTH',          # use refresh token authentication flow
            AuthParameters={'REFRESH_TOKEN': session['refresh_token']}  # provide refresh token
        )
        auth = resp['AuthenticationResult']         # extract new tokens from response
        session['access_token'] = auth['AccessToken']  # store new access token in session
        session['id_token']    = auth['IdToken']    # store new ID token in session
        return True                                 # indicate successful token refresh
    except Exception as e:                          # handle any Cognito API errors
        logger.error(f"Token refresh error: {e}", exc_info=True)  # log the error details
        return False                                # indicate failed token refresh



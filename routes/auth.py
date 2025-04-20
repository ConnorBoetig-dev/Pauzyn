# ============================================================================
# IMPORTS SECTION
# ============================================================================

# Flask imports for web functionality:
#   - Blueprint: Class for modular route organization
#   - render_template: Function to render HTML templates
#   - redirect: Function for URL redirections
#   - url_for: Function to build URLs dynamically
#   - request: Object to handle HTTP requests
#   - flash: Function for temporary user messages
#   - session: Dictionary-like object for user session management
from flask import Blueprint, render_template, redirect, url_for, request, flash, session

# Core Python imports:
#   - os: For environment variable access
#   - hmac, hashlib, base64: For cryptographic operations
#   - json: For JSON data handling
#   - uuid: For generating unique identifiers
#   - datetime: For timestamp handling
import os
import hmac
import hashlib
import base64
import json
import uuid
from datetime import datetime

# AWS related imports:
#   - boto3: AWS SDK for Python
#   - botocore.exceptions: For handling AWS-specific errors
import boto3
import botocore.exceptions

# Third-party imports:
#   - requests: HTTP library for making API calls
import requests

# Configure logging
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# ============================================================================
# BLUEPRINT CONFIGURATION
# ============================================================================

# Create a Blueprint instance named 'auth'
# - 'auth' is the Blueprint name
# - __name__ is the Blueprint's import name
# This Blueprint will handle all authentication-related routes
auth_bp = Blueprint('auth', __name__)

# ============================================================================
# AWS COGNITO CONFIGURATION
# ============================================================================

# Load AWS Cognito configuration from environment variables
# These variables should be set in your .env file
USER_POOL_ID = os.getenv('COGNITO_USER_POOL_ID')      # Cognito User Pool identifier
CLIENT_ID = os.getenv('COGNITO_CLIENT_ID')            # Application's client ID
CLIENT_SECRET = os.getenv('COGNITO_CLIENT_SECRET')    # Application's client secret
REGION = os.getenv('AWS_REGION')                      # AWS region (e.g., us-east-1)

# Initialize the Cognito Identity Provider client
# This client will be used to interact with Cognito services
client = boto3.client('cognito-idp', region_name=REGION)

# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user authentication via custom login form with Cognito backend
    
    Flow:
    1. User submits email/password through custom form
    2. Backend validates with Cognito using USER_PASSWORD_AUTH flow
    3. On success: Store tokens and redirect to home
    4. On failure: Show appropriate error message
    
    Returns:
        GET: Login form template
        POST: Redirect to home (success) or back to login (failure)
    """
    if request.method == 'POST':
        # Extract credentials from form submission
        # These field names must match your HTML form's "name" attributes
        email = request.form['email']
        password = request.form['password']

        try:
            secret_hash = get_secret_hash(email)
            
            response = client.initiate_auth(
                ClientId=CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': password,
                    'SECRET_HASH': secret_hash
                }
            )

            # Extract authentication tokens from successful response
            auth_result = response['AuthenticationResult']
            
            # Store tokens in Flask session for subsequent requests
            # - access_token: Short-lived token for API access
            # - id_token: Contains user information (JWT)
            # - refresh_token: Long-lived token to get new access tokens
            session['access_token'] = auth_result['AccessToken']
            session['id_token'] = auth_result['IdToken']
            session['refresh_token'] = auth_result['RefreshToken']
            
            # Decode the ID token to get user information
            # The ID token is a JWT that contains user information
            import jwt
            id_token = auth_result['IdToken']
            decoded_token = jwt.decode(id_token, options={"verify_signature": False})
            
            # Store user's name in session
            session['user_name'] = decoded_token.get('name', 'User')
            
            flash('Login successful!', 'success')
            return redirect(url_for('home'))

        except client.exceptions.NotAuthorizedException:
            # Handles invalid credentials
            # This exception occurs when username exists but password is wrong
            flash('Incorrect username or password', 'danger')
            
        except client.exceptions.UserNotConfirmedException:
            # Handles unconfirmed user accounts
            # This occurs when user hasn't verified their email address
            flash('Please confirm your account via email before logging in.', 'warning')
            
        except client.exceptions.UserNotFoundException:
            # Handles non-existent username
            # For security, we use the same message as wrong password
            flash('Incorrect username or password', 'danger')
            
        except client.exceptions.InvalidParameterException:
            # Handles malformed input
            flash('Invalid login parameters. Please check your input.', 'danger')
            
        except Exception as e:
            # Catches any unexpected errors
            # In production, you might want to log this error
            flash(f'An unexpected error occurred. Please try again later.', 'danger')
            print(f"Login error: {str(e)}")  # For debugging

    # For GET requests or failed POST requests, show the login form
    return render_template('auth/login.html')

def get_secret_hash(username):
    """Calculate the secret hash for Cognito authentication"""
    msg = username + CLIENT_ID
    dig = hmac.new(
        str(CLIENT_SECRET).encode('utf-8'), 
        msg=msg.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle new user registration with Cognito"""
    logger.info("Signup route accessed")
    
    if request.method == 'POST':
        # Extract form data
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        
        logger.info(f"Form data received - Email: {email}, Name: {name}")
        
        try:
            # Calculate secret hash
            secret_hash = get_secret_hash(email)
            
            # Register user with Cognito
            logger.info("Attempting Cognito signup...")
            
            response = client.sign_up(
                ClientId=CLIENT_ID,
                Username=email,
                Password=password,
                SecretHash=secret_hash,
                UserAttributes=[
                    {'Name': 'name', 'Value': name},
                    {'Name': 'email', 'Value': email},
                    {'Name': 'preferred_username', 'Value': email}
                ]
            )
            
            logger.info(f"Cognito signup response: {response}")
            
            session['temp_email'] = email
            flash('Registration successful! Please check your email for verification code.', 'success')
            return redirect(url_for('auth.confirm'))
            
        except client.exceptions.UsernameExistsException as e:
            logger.error(f"Username exists error: {str(e)}")
            flash('An account with this email already exists.', 'danger')
            return redirect(url_for('auth.signup'))
        except client.exceptions.InvalidPasswordException as e:
            logger.error(f"Invalid password error: {str(e)}")
            flash('Password must be at least 8 characters long and contain numbers, special characters, uppercase and lowercase letters.', 'danger')
            return redirect(url_for('auth.signup'))
        except Exception as e:
            logger.error(f"Unexpected error during signup: {str(e)}", exc_info=True)
            logger.error(f"Error type: {type(e)}")
            logger.error(f"Error details: {e.__dict__}")
            flash(f'Registration error: {str(e)}', 'danger')
            return redirect(url_for('auth.signup'))
            
    return render_template('auth/signup.html')

@auth_bp.route('/confirm', methods=['GET', 'POST'])
def confirm():
    """Handle email verification for new users
    
    Flow:
    1. User receives verification code via email
    2. User submits code through confirmation form
    3. Verify code with Cognito
    4. Redirect to login upon success
    
    Returns:
        GET: Confirmation code form
        POST: Redirect to login or back to form with errors
    """
    if 'temp_email' not in session:
        flash('Please sign up first.', 'warning')
        return redirect(url_for('auth.signup'))
        
    if request.method == 'POST':
        code = request.form['code']
        email = session['temp_email']
        
        try:
            # Verify the confirmation code with Cognito
            client.confirm_sign_up(
                ClientId=CLIENT_ID,
                Username=email,
                ConfirmationCode=code
            )
            
            # Clear temporary email from session
            session.pop('temp_email', None)
            
            flash('Email verified! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
            
        except client.exceptions.CodeMismatchException:
            flash('Invalid verification code. Please try again.', 'danger')
        except client.exceptions.ExpiredCodeException:
            flash('Verification code has expired. Please request a new one.', 'danger')
        except Exception as e:
            flash('An error occurred during verification.', 'danger')
            print(f"Confirmation error: {str(e)}")  # For debugging
            
    return render_template('auth/confirm.html')

@auth_bp.route('/logout')
def logout():
    """Handle user logout functionality"""
    # Clear all session data
    session.clear()
    
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('home'))

# ============================================================================
# HELPER FUNCTIONS FOR TOKEN MANAGEMENT
# ============================================================================

def is_token_valid():
    """Check if the current session has valid tokens
    
    Returns:
        bool: True if valid tokens exist, False otherwise
    """
    return 'access_token' in session and 'id_token' in session

def refresh_tokens():
    """Refresh expired access tokens using refresh token
    
    Returns:
        bool: True if refresh successful, False otherwise
    """
    if 'refresh_token' not in session:
        return False
        
    try:
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='REFRESH_TOKEN_AUTH',
            AuthParameters={
                'REFRESH_TOKEN': session['refresh_token']
            }
        )
        
        # Update session with new tokens
        auth_result = response['AuthenticationResult']
        session['access_token'] = auth_result['AccessToken']
        session['id_token'] = auth_result['IdToken']
        return True
        
    except Exception as e:
        print(f"Token refresh error: {str(e)}")
        return False

# ============================================================================
# HELPER FUNCTIONS (To be implemented)
# ============================================================================

# TODO: Add helper functions for:
#   - Password hashing
#   - Token validation
#   - Cognito API interactions
#   - Error handling


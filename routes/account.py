# ------------------- IMPORTS AND DEPENDENCIES ---------------------------
# Core Flask imports for routing, templates, and session management,
# plus JWT handling for user authentication

from flask import Blueprint, render_template, redirect, url_for, flash, session
import jwt
import logging

# ------------------- LOGGING CONFIGURATION ---------------------------
# Sets up debug-level logging for the account management system
# to track user actions and potential issues

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# ------------------- BLUEPRINT SETUP ---------------------------
# Creates the account blueprint that handles all account-related
# functionality, including profile viewing and management

account_bp = Blueprint('account', __name__)

# ------------------- CORE ACCOUNT ROUTES ---------------------------
# Main account management routes that handle user profile display
# and account information retrieval from Cognito tokens

@account_bp.route('/')
def index():
    """Handle account page display"""
    if 'id_token' not in session:                    # check for valid user session
        flash('Please login to view your account.', 'warning')  # inform user they need to login
        return redirect(url_for('auth.login'))       # redirect to login page
        
    # Decode the ID token to get user information
    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    
    return render_template('account/index.html', user_info=decoded_token)  # display account page

# ------------------- PLANNED ACCOUNT FEATURES ---------------------------
# Future account management endpoints to be implemented:
# - Profile management (/profile)
# - Subscription handling (/subscription)
# - Usage tracking (/usage)
# 
# @account_bp.route('/profile')
# @account_bp.route('/subscription')
# @account_bp.route('/usage')
# etc.

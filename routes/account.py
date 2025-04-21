from flask import Blueprint, render_template, redirect, url_for, flash, session
import jwt
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create a Blueprint instance for account routes
account_bp = Blueprint('account', __name__)

@account_bp.route('/')
def index():
    """Handle account page display"""
    if 'id_token' not in session:
        flash('Please login to view your account.', 'warning')
        return redirect(url_for('auth.login'))
        
    # Decode the ID token to get user information
    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    
    return render_template('account/index.html', user_info=decoded_token)

# Add more account-related routes here
# @account_bp.route('/profile')
# @account_bp.route('/subscription')
# @account_bp.route('/usage')
# etc.
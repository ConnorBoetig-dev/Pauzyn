# ------------------- IMPORTS AND DEPENDENCIES ---------------------------
from flask import Blueprint, render_template, redirect, url_for, flash, session  # Flask routing, templates, sessions
import jwt                                                                       # Token decode utility
import logging                                                                   # Built‑in logging

# ------------------- LOGGING CONFIGURATION ---------------------------
logging.basicConfig(level=logging.DEBUG)                                         # Global DEBUG log level
logger = logging.getLogger(__name__)                                             # Module‑level logger

# ------------------- BLUEPRINT SETUP ---------------------------
account_bp = Blueprint('account', __name__)                                      # Register as 'account' blueprint

# ------------------- CORE ACCOUNT ROUTES ---------------------------
@account_bp.route('/')                                                            # Dashboard root → /account/
def index():
    """Render the logged‑in user’s account page"""                        # Docstring for function
    if 'id_token' not in session:                                                 # No JWT in session?
        flash('Please login to view your account.', 'warning')                    #  Notify and
        return redirect(url_for('auth.login'))                                    #  redirect to /auth/login

    # Decode the (already‑verified) Cognito ID token just for displaying claims
    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})  # ⚠ skipping sig check only for local use

    return render_template('account/index.html', user_info=decoded_token)        # Pass claims to template

# ------------------- PLANNED ACCOUNT FEATURES ---------------------------
# @account_bp.route('/profile')                                                   # Future: edit profile
# @account_bp.route('/subscription')                                              # Future: manage plan
# @account_bp.route('/usage')                                                     # Future: usage dashboard


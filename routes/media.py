# ------------------- IMPORTS AND DEPENDENCIES ---------------------------
# Core Flask components, AWS S3 integration, and utilities for
# file handling and user authentication

from flask import Blueprint, jsonify, request, render_template, session, redirect, url_for
import boto3
from botocore.config import Config
from uuid import uuid4
from datetime import datetime
from functools import wraps
import jwt

# ------------------- AUTHENTICATION DECORATOR ---------------------------
# Custom decorator that ensures users are logged in before accessing
# media-related functionality. Redirects to login if session is invalid

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'id_token' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

# ------------------- AWS S3 CONFIGURATION ---------------------------
# Sets up the S3 client with specific regional endpoint and
# virtual-style addressing for proper bucket access

s3_config = Config(
    region_name="us-east-2",
    signature_version="s3v4",
    s3={"addressing_style": "virtual"}  # Uses bucketname.s3.us-east-2.amazonaws.com
)

# ------------------- BLUEPRINT SETUP ---------------------------
# Creates the media blueprint and initializes the S3 client
# for handling file uploads and media management

media_bp = Blueprint('media', __name__)
s3_client = boto3.client('s3', config=s3_config)

# ------------------- MEDIA UPLOAD INTERFACE ---------------------------
# Renders the upload page where users can drag and drop or select
# files for upload to their media gallery

@media_bp.route('/upload')
@login_required
def upload_page():
    return render_template('media/upload.html')

# ------------------- S3 PRESIGNED URL GENERATION ---------------------------
# Generates secure, temporary URLs for direct browser-to-S3 uploads
# Includes user-specific paths and unique identifiers for each file

@media_bp.route('/api/media/presigned-url', methods=['POST'])
@login_required
def get_presigned_url():
    # Extract file information from request
    file_name = request.json.get('fileName')
    file_type = request.json.get('fileType')
    
    # Validate required parameters
    if not file_name or not file_type:
        return jsonify({'error': 'Missing fileName or fileType'}), 400
    
    # Get user ID from session token for user-specific storage
    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    user_id = decoded_token.get('sub')
    
    # Generate unique file path with timestamp and UUID
    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    unique_id = str(uuid4())[:8]
    file_key = f"users/{user_id}/{timestamp}-{unique_id}-{file_name}"
    
    try:
        # Generate temporary signed URL for direct upload
        presigned_url = s3_client.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': 'pauzynbucket',
                'Key': file_key,
                'ContentType': file_type  # Ensures proper content type on S3
            },
            ExpiresIn=300,  # URL expires in 5 minutes
            HttpMethod='PUT'
        )
        
        # Return URL and file key to client
        return jsonify({
            'presignedUrl': presigned_url,
            'fileKey': file_key
        })
    except Exception as e:
        # Log and return any errors during URL generation
        print(f"Error generating presigned URL: {str(e)}")
        return jsonify({'error': str(e)}), 500





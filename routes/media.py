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
from flask import current_app
import json

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
    file_name = request.json.get('fileName')
    file_type = request.json.get('fileType')
    
    if not file_name or not file_type:
        return jsonify({'error': 'Missing fileName or fileType'}), 400
    
    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    user_id = decoded_token.get('sub')
    
    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    unique_id = str(uuid4())[:8]
    file_key = f"users/{user_id}/{timestamp}-{unique_id}-{file_name}"
    
    try:
        presigned_url = s3_client.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': 'pauzynbucket',
                'Key': file_key,
                'ContentType': file_type
            },
            ExpiresIn=300,
            HttpMethod='PUT'
        )
        
        # Record pending upload in DynamoDB
        media_id = current_app.db_manager.record_media_upload(
            user_id=user_id,
            file_name=file_name,
            file_type=file_type,
            s3_location=file_key
        )
        
        if not media_id:
            raise Exception("Failed to record media upload")
        
        return jsonify({
            'presignedUrl': presigned_url,
            'fileKey': file_key,
            'mediaId': media_id
        })
    except Exception as e:
        print(f"Error generating presigned URL: {str(e)}")
        return jsonify({'error': str(e)}), 500

@media_bp.route('/api/media/upload-complete', methods=['POST'])
@login_required
def upload_complete():
    media_id = request.json.get('mediaId')
    file_size = request.json.get('fileSize')
    
    if not media_id or not file_size:
        return jsonify({'error': 'Missing mediaId or fileSize'}), 400
    
    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    user_id = decoded_token.get('sub')
    
    # Update media status
    success = current_app.db_manager.update_media_processing_status(
        user_id=user_id,
        media_id=media_id,
        status='uploaded',
        metadata={'file_size': file_size}
    )
    
    # Track usage statistics
    usage_updated = current_app.db_manager.update_usage_stats(
        user_id=user_id,
        file_size=file_size,
        operation='upload'
    )
    
    if success and usage_updated:
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to update media status or usage'}), 500

@media_bp.route('/api/media/list', methods=['GET'])
@login_required
def list_media():
    limit = int(request.args.get('limit', 50))
    last_key = request.args.get('lastKey')
    
    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    user_id = decoded_token.get('sub')
    
    if last_key:
        try:
            last_key = json.loads(last_key)
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid lastKey format'}), 400
    
    result = current_app.db_manager.get_user_media(
        user_id=user_id,
        limit=limit,
        last_evaluated_key=last_key
    )
    
    response = {
        'items': result['items'],
        'hasMore': 'last_evaluated_key' in result
    }
    
    if 'last_evaluated_key' in result:
        response['lastKey'] = json.dumps(result['last_evaluated_key'])
    


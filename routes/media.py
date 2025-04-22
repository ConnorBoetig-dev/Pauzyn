# ------------------- IMPORTS AND DEPENDENCIES ---------------------------
from flask import Blueprint, jsonify, request, render_template, session, redirect, url_for  # Flask primitives & helpers
import boto3                                                                             # AWS SDK for Python
from botocore.config import Config                                                      # Fine‑tune boto3 client
from uuid import uuid4                                                                   # Generate unique IDs
from datetime import datetime                                                             # Timestamps
from functools import wraps                                                               # Decorator helper
import jwt                                                                               # Decode Cognito JWTs
from flask import current_app                                                             # Access app context (db_manager)
import json                                                                              # Handle JSON for pagination keys

# ------------------- AUTHENTICATION DECORATOR ---------------------------

def login_required(f):                                                                   # restrict routes to logged‑in users
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'id_token' not in session:                                                   # no session token → not logged in
            return redirect(url_for('auth.login'))                                       # send user to login page
        return f(*args, **kwargs)                                                        # else proceed
    return decorated_function

# ------------------- AWS S3 CONFIGURATION ---------------------------

s3_config = Config(                                                                      # boto3 config w/ region & style
    region_name="us-east-2",                                                            # bucket lives in Ohio
    signature_version="s3v4",                                                           # presigned‑URL signature algo
    s3={"addressing_style": "virtual"}                                               # bucketname.s3.us‑east‑2.amazonaws.com
)

# ------------------- BLUEPRINT SETUP ---------------------------

media_bp = Blueprint('media', __name__)                                                  # /media blueprint
s3_client = boto3.client('s3', config=s3_config)                                         # S3 client instance

# ------------------- MEDIA UPLOAD INTERFACE ---------------------------

@media_bp.route('/upload')                                                               # GET /media/upload
@login_required
def upload_page():
    return render_template('media/upload.html')                                          # render drag‑and‑drop UI

# ------------------- S3 PRESIGNED URL GENERATION ---------------------------

@media_bp.route('/api/media/presigned-url', methods=['POST'])                            # POST JSON → presigned URL
@login_required
def get_presigned_url():
    file_name = request.json.get('fileName')                                             # original filename
    file_type = request.json.get('fileType')                                             # MIME type

    if not file_name or not file_type:                                                   # validate payload
        return jsonify({'error': 'Missing fileName or fileType'}), 400

    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})  # get user info
    user_id = decoded_token.get('sub')                                                   # Cognito user UUID

    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')                              # YYYYMMDD‑HHMMSS
    unique_id = str(uuid4())[:8]                                                         # short random ID
    file_key = f"users/{user_id}/{timestamp}-{unique_id}-{file_name}"                   # S3 object key

    try:
        presigned_url = s3_client.generate_presigned_url(                                # make PUT URL
            'put_object',
            Params={
                'Bucket': 'pauzynbucket',                                                # target bucket
                'Key': file_key,                                                         # object key
                'ContentType': file_type                                                 # enforce MIME type
            },
            ExpiresIn=300,                                                               # 5‑minute expiry
            HttpMethod='PUT'
        )

        # Record pending upload in DynamoDB
        media_id = current_app.db_manager.record_media_upload(                           # log "pending" item
            user_id=user_id,
            file_name=file_name,
            file_type=file_type,
            s3_location=file_key
        )

        if not media_id:                                                                 # write failed
            raise Exception("Failed to record media upload")

        return jsonify({
            'presignedUrl': presigned_url,
            'fileKey': file_key,
            'mediaId': media_id
        })                                                                                # success payload
    except Exception as e:
        print(f"Error generating presigned URL: {str(e)}")                              # quick console log
        return jsonify({'error': str(e)}), 500                                           # generic 500

# ------------------- S3 UPLOAD COMPLETE CALLBACK ---------------------------

@media_bp.route('/api/media/upload-complete', methods=['POST'])
@login_required
def upload_complete():
    media_id = request.json.get('mediaId')
    file_size = request.json.get('fileSize')
    
    print(f"Upload complete - mediaId: {media_id}, size: {file_size}")  # Debug log
    
    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    user_id = decoded_token.get('sub')
    
    success = current_app.db_manager.update_media_processing_status(
        user_id=user_id,
        media_id=media_id,
        status='uploaded',
        metadata={'file_size': file_size}
    )
    
    print(f"Status update success: {success}")  # Debug log
    
    if not success:
        return jsonify({'error': 'Failed to update media status'}), 500
        
    return jsonify({'success': True})

# ------------------- PAGINATED MEDIA LIST ENDPOINT ---------------------------

@media_bp.route('/api/media/list', methods=['GET'])
@login_required
def list_media():
    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    user_id = decoded_token.get('sub')
    
    # Get query parameters
    media_type = request.args.get('type', 'all')
    sort_by = request.args.get('sort', 'date')
    last_key_str = request.args.get('lastKey')
    
    # Parse the last evaluated key if provided
    last_evaluated_key = None
    if last_key_str:
        try:
            last_evaluated_key = json.loads(last_key_str)
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid lastKey format'}), 400
    
    print(f"Fetching media for user: {user_id}, type: {media_type}, sort: {sort_by}")
    
    result = current_app.db_manager.get_user_media(
        user_id=user_id,
        limit=50,
        last_evaluated_key=last_evaluated_key
    )
    
    transformed_items = []
    for item in result.get('items', []):
        # Skip items that don't match the filter
        if media_type != 'all':
            item_type = 'image' if item.get('file_type', '').startswith('image') else 'video'
            if item_type != media_type:
                continue
                
        # Generate a presigned URL for viewing the media
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': 'pauzynbucket',
                'Key': item.get('s3_location'),
                'ResponseContentDisposition': 'inline',
                'ResponseContentType': item.get('file_type')
            },
            ExpiresIn=3600  # 1 hour
        )

        transformed_item = {
            'id': item.get('mediaID'),
            'filename': item.get('file_name'),
            'type': 'image' if item.get('file_type', '').startswith('image') else 'video',
            'url': presigned_url,
            'lastModified': item.get('updated_at'),
            'size': item.get('file_size', 0)
        }
        transformed_items.append(transformed_item)

    # Sort the items
    if sort_by == 'name':
        transformed_items.sort(key=lambda x: x.get('filename', ''))
    else:  # sort by date
        transformed_items.sort(key=lambda x: x.get('lastModified', ''), reverse=True)

    response = {
        'items': transformed_items,
        'hasMore': 'last_evaluated_key' in result
    }

    if 'last_evaluated_key' in result:
        response['lastKey'] = json.dumps(result['last_evaluated_key'])

    return jsonify(response)

@media_bp.route('/gallery')
@login_required
def gallery_page():
    """Render the media gallery interface."""
    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    user_id = decoded_token.get('sub')
    
    print(f"Gallery page - fetching media for user: {user_id}")  # Debug log
    
    result = current_app.db_manager.get_user_media(
        user_id=user_id,
        limit=50
    )
    
    initial_items = []
    for item in result.get('items', []):
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': 'pauzynbucket',
                'Key': item.get('s3_location'),
                'ResponseContentDisposition': 'inline',
                'ResponseContentType': item.get('file_type')
            },
            ExpiresIn=3600  # 1 hour
        )
        
        print(f"Gallery page presigned URL: {presigned_url}")  # Debug log
        print(f"For file: {item.get('file_name')} of type: {item.get('file_type')}")  # Debug log

        initial_items.append({
            'id': item.get('mediaID'),
            'filename': item.get('file_name'),
            'type': 'image' if item.get('file_type', '').startswith('image') else 'video',
            'url': presigned_url,
            'lastModified': item.get('updated_at'),
            'size': item.get('file_size', 0)
        })
    
    return render_template(
        'media/gallery.html',
        initial_items=initial_items,
        has_more='last_evaluated_key' in result
    )

@media_bp.route('/api/media/refresh-url/<media_id>')
@login_required
def refresh_media_url(media_id):
    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    user_id = decoded_token.get('sub')
    
    # Get the media item from DynamoDB
    result = current_app.db_manager.get_user_media(
        user_id=user_id,
        limit=50
    )
    
    # Find the media item with the matching ID
    media_item = next((item for item in result.get('items', []) if item.get('mediaID') == media_id), None)
    
    if not media_item:
        return jsonify({'error': 'Media not found'}), 404
        
    # Generate a new presigned URL
    presigned_url = s3_client.generate_presigned_url(
        'get_object',
        Params={
            'Bucket': 'pauzynbucket',
            'Key': media_item.get('s3_location'),
            'ResponseContentDisposition': 'inline',
            'ResponseContentType': media_item.get('file_type')
        },
        ExpiresIn=3600  # 1 hour
    )
    
    return jsonify({'url': presigned_url})

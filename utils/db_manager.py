# ------------------- IMPORTS AND DEPENDENCIES ---------------------------
# Core AWS SDK for DynamoDB access, error handling, and utilities for
# logging and datetime operations

import boto3                                        # AWS SDK for Python
from botocore.exceptions import ClientError         # AWS-specific error handling
import logging                                      # std-lib logging for debug/info
from datetime import datetime                       # timestamp generation
import os                                          # environment variable access
import uuid

logger = logging.getLogger(__name__)               # module-level logger instance

# ------------------- DATABASE MANAGER CLASS ---------------------------
# Central class for handling all DynamoDB operations including user management,
# media tracking, and usage statistics

class DynamoDBManager:
    def __init__(self, region_name):
        self.dynamodb = boto3.resource('dynamodb', region_name=region_name)  # initialize DynamoDB connection
        self.users_table = self.dynamodb.Table(os.getenv('DYNAMODB_USERS_TABLE'))     # users table reference
        self.media_table = self.dynamodb.Table(os.getenv('DYNAMODB_MEDIA_TABLE'))     # media table reference
        self.usage_table = self.dynamodb.Table(os.getenv('DYNAMODB_USAGE_TABLE'))     # usage stats table reference

    # ------------------- USER MANAGEMENT OPERATIONS ---------------------------
    # Methods for creating and managing user records in DynamoDB, including
    # basic profile information and timestamps

    def create_user(self, user_id, email, name):
        """Create a new user record in DynamoDB."""
        try:
            timestamp = datetime.utcnow().isoformat()
            self.users_table.put_item(
                Item={
                    'userID': user_id,          # Partition key
                    'SK': 'PROFILE',            # Sort key
                    'email': email,
                    'name': name,
                    'created_at': timestamp,
                    'updated_at': timestamp
                }
            )
            return True
        except ClientError as e:
            logger.error(f"Failed to create user: {str(e)}")
            return False

    # ------------------- MEDIA MANAGEMENT OPERATIONS ---------------------------
    # Methods for tracking and updating media uploads, including status updates
    # and metadata management

    def record_media_upload(self, user_id, file_name, file_type, s3_location):
        """Record a new media upload."""
        try:
            timestamp = datetime.utcnow().isoformat()
            item = {
                'userID': user_id,         # Changed from user_ID to userID
                'mediaID': s3_location,    # Changed from media_id to mediaID
                'file_name': file_name,
                'file_type': file_type,
                's3_location': s3_location,
                'file_size': 0,
                'status': 'pending',
                'created_at': timestamp,
                'updated_at': timestamp
            }
            self.media_table.put_item(Item=item)
            return s3_location
        except ClientError as e:
            logger.error(f"Failed to record media upload: {str(e)}")
            return None

    def update_media_processing_status(self, user_id, media_id, status, metadata=None):
        """Update media processing status and metadata."""
        try:
            update_expression = "SET #status = :status, updated_at = :updated_at"
            expression_values = {
                ':status': status,
                ':updated_at': datetime.utcnow().isoformat()
            }

            if metadata:
                for key, value in metadata.items():
                    update_expression += f", #{key} = :{key}"
                    expression_values[f":{key}"] = value

            self.media_table.update_item(
                Key={
                    'userID': user_id,     # Changed from user_id to userID
                    'mediaID': media_id    # Changed from media_id to mediaID
                },
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ExpressionAttributeNames={
                    '#status': 'status',
                    **{f"#{k}": k for k in (metadata or {}).keys()}
                }
            )
            return True
        except ClientError as e:
            logger.error(f"Failed to update media status: {str(e)}")
            return False

    def get_user_media(self, user_id, limit=50, last_evaluated_key=None):
        """Get user's media items with pagination."""
        try:
            params = {
                'KeyConditionExpression': 'userID = :userID',  # Changed from user_id to userID
                'ExpressionAttributeValues': {':userID': user_id},  # Changed key name
                'Limit': limit
            }

            if last_evaluated_key:
                params['ExclusiveStartKey'] = last_evaluated_key

            response = self.media_table.query(**params)
            
            return {
                'items': response.get('Items', []),
                'last_evaluated_key': response.get('LastEvaluatedKey')
            }
        except ClientError as e:
            logger.error(f"Failed to get user media: {str(e)}")
            return {'items': []}

    # ------------------- USAGE TRACKING OPERATIONS ---------------------------
    # Methods for tracking user storage usage and upload counts

    def update_usage_stats(self, user_id, file_size, operation='upload'):
        """Update user's usage statistics."""
        try:
            timestamp = datetime.utcnow().isoformat()
            month_key = datetime.utcnow().strftime('%Y-%m')
            
            response = self.usage_table.update_item(
                Key={
                    'userID': user_id,
                    'SK': month_key
                },
                UpdateExpression="""
                    ADD total_bytes :size, 
                        upload_count :upload_count
                    SET updated_at = :timestamp
                """,
                ExpressionAttributeValues={
                    ':size': file_size,
                    ':upload_count': 1,
                    ':timestamp': timestamp
                },
                ReturnValues='UPDATED_NEW'
            )
            return True
        except ClientError as e:
            logger.error(f"Failed to update usage stats: {str(e)}")
            return False

    def get_usage_stats(self, user_id, month=None):
        """Get user's usage statistics for a specific month."""
        if month is None:
            month = datetime.utcnow().strftime('%Y-%m')
        
        try:
            response = self.usage_table.get_item(
                Key={
                    'user_id': user_id,
                    'month': month
                }
            )
            return response.get('Item', {
                'total_bytes': 0,
                'upload_count': 0
            })
        except ClientError as e:
            logger.error(f"Failed to get usage stats: {str(e)}")
            return None

    def test_media_table_connection(self):
        """Test connection to media table with correct schema."""
        try:
            test_id = str(uuid.uuid4())
            self.media_table.put_item(
                Item={
                    'userID': 'test_user',
                    'mediaID': test_id,
                    'test': True
                }
            )
            
            # Verify the item was written
            response = self.media_table.get_item(
                Key={
                    'userID': 'test_user',
                    'mediaID': test_id
                }
            )
            
            # Clean up test item
            self.media_table.delete_item(
                Key={
                    'userID': 'test_user',
                    'mediaID': test_id
                }
            )
            
            return 'Item' in response
        except Exception as e:
            logger.error(f"Test failed: {str(e)}")
            return False






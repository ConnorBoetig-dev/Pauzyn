// When uploading to the presigned URL
const response = await fetch(presignedUrl, {
    method: 'PUT',
    body: file,
    headers: {
        'Content-Type': file.type  // Only include Content-Type, remove x-amz-acl
    }
});
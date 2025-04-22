// ------------------- UPLOAD VIA PRESIGNED URL ---------------------------
// This snippet uploads a File object directly from the browser to S3 using the
// presigned URL that your Flask backend generated. The presigned URL already
// contains a temporary signature and object key, so the browser can PUT the
// object without needing AWS credentials.
//
// Parameters expected to exist in scope:
//   • presignedUrl – time‑limited, single‑use HTTPS URL from /api/media/presigned-url
//   • file         – JavaScript File object (e.g., from <input type="file">)
//
// The only header we explicitly set is Content‑Type so S3 stores the correct
// MIME type. ACL is omitted because bucket policy handles permissions, and any
// extra headers would invalidate the signature.
//
// The Fetch API returns a Response object; callers should check response.ok to
// verify success and then notify the backend via /api/media/upload-complete.

// When uploading to the presigned URL
const response = await fetch(presignedUrl, {   // make the PUT request directly to S3
    method: 'PUT',                             // S3 presigned URL expects HTTP PUT
    body: file,                               // raw file bytes streamed in request body
    headers: {
        'Content-Type': file.type             // send the file’s MIME type (e.g., image/jpeg)
    }
});                                            // response.ok === true ⇒ upload succeeded

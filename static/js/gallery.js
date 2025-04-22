class GalleryManager {
    constructor() {
        this.refreshInterval = 30 * 60 * 1000; // Refresh URLs every 30 minutes
        this.setupRefreshTimer();
    }

    setupRefreshTimer() {
        // Initial refresh after 25 minutes (before the 1-hour expiry)
        setTimeout(() => this.refreshUrls(), 25 * 60 * 1000);
        // Then refresh every 30 minutes
        setInterval(() => this.refreshUrls(), this.refreshInterval);
    }

    async refreshUrls() {
        const galleryItems = document.querySelectorAll('.gallery-item');
        
        for (const item of galleryItems) {
            const mediaId = item.dataset.id;
            try {
                const response = await fetch(`/api/media/refresh-url/${mediaId}`);
                if (response.ok) {
                    const data = await response.json();
                    // Update the image/video source
                    const mediaElement = item.querySelector('img, video');
                    if (mediaElement) {
                        mediaElement.src = data.url;
                    }
                }
            } catch (error) {
                console.error('Failed to refresh URL for item:', mediaId);
            }
        }
    }
}

// Initialize the gallery manager when the page loads
document.addEventListener('DOMContentLoaded', () => {
    const gallery = new GalleryManager();
});
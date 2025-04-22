class GalleryManager {
    constructor() {
        this.refreshInterval = 30 * 60 * 1000; // 30 minutes
        this.setupRefreshTimer();
        this.setupVisibilityHandler();
    }

    setupRefreshTimer() {
        // Initial refresh after 25 minutes
        setTimeout(() => this.refreshUrls(), 25 * 60 * 1000);
        // Then refresh every 30 minutes
        setInterval(() => this.refreshUrls(), this.refreshInterval);
    }

    setupVisibilityHandler() {
        // Refresh URLs when page becomes visible after being hidden
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
                this.refreshUrls();
            }
        });
    }

    async refreshUrls() {
        const galleryItems = document.querySelectorAll('.gallery-item');
        
        const refreshPromises = Array.from(galleryItems).map(async (item) => {
            const mediaId = item.dataset.id;
            try {
                const response = await fetch(`/api/media/refresh-url/${mediaId}`);
                if (response.ok) {
                    const data = await response.json();
                    const mediaElement = item.querySelector('img, video');
                    if (mediaElement) {
                        mediaElement.src = data.url;
                    }
                }
            } catch (error) {
                console.error('Failed to refresh URL for item:', mediaId, error);
            }
        });

        await Promise.all(refreshPromises);
    }
}

// Initialize the gallery manager when the page loads
document.addEventListener('DOMContentLoaded', () => {
    const gallery = new GalleryManager();
});

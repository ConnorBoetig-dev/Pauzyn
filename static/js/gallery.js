class GalleryManager {
    constructor() {
        this.lightbox = document.getElementById('lightbox');
        this.lightboxMediaContainer = document.querySelector('.lightbox-media-container');
        this.lightboxCaption = document.querySelector('.lightbox-caption');
        this.lightboxCounter = document.querySelector('.lightbox-counter');
        this.lightboxClose = document.querySelector('.lightbox-close');
        this.lightboxPrev = document.querySelector('.lightbox-prev');
        this.lightboxNext = document.querySelector('.lightbox-next');
        
        this.currentIndex = 0;
        this.galleryItems = [];
        this.refreshInterval = 30 * 60 * 1000; // 30 minutes
        
        this.initializeEventListeners();
        this.setupRefreshTimer();
        this.setupVisibilityHandler();
    }

    initializeEventListeners() {
        this.lightboxClose.addEventListener('click', () => this.closeLightbox());
        this.lightboxPrev.addEventListener('click', () => this.navigate(-1));
        this.lightboxNext.addEventListener('click', () => this.navigate(1));
        
        this.lightbox.addEventListener('click', (e) => {
            // Close if clicked element is the lightbox background or lightbox-content
            // But don't close if clicked on media, navigation arrows, or caption
            if (e.target === this.lightbox || 
                e.target.classList.contains('lightbox-content')) {
                this.closeLightbox();
            }
        });

        document.addEventListener('keydown', (e) => {
            if (!this.lightbox.classList.contains('active')) return;
            
            if (e.key === 'Escape') {
                this.closeLightbox();
            } else if (e.key === 'ArrowLeft') {
                this.navigate(-1);
            } else if (e.key === 'ArrowRight') {
                this.navigate(1);
            }
        });

        // Re-attach listeners when gallery items change
        const mediaTypeFilter = document.getElementById('mediaTypeFilter');
        const sortOrder = document.getElementById('sortOrder');
        
        if (mediaTypeFilter) {
            mediaTypeFilter.addEventListener('change', () => {
                setTimeout(() => this.attachItemClickListeners(), 500);
            });
        }
        
        if (sortOrder) {
            sortOrder.addEventListener('change', () => {
                setTimeout(() => this.attachItemClickListeners(), 500);
            });
        }
    }

    openLightbox(index) {
        this.galleryItems = Array.from(document.querySelectorAll('.gallery-item'));
        if (this.galleryItems.length === 0) return;
        
        this.currentIndex = index;
        this.updateLightboxContent();
        
        this.lightbox.classList.add('active');
        document.body.style.overflow = 'hidden';
        
        const videoElement = this.lightboxMediaContainer.querySelector('video');
        if (videoElement) {
            videoElement.play();
        }
    }

    closeLightbox() {
        const videoElement = this.lightboxMediaContainer.querySelector('video');
        if (videoElement) {
            videoElement.pause();
        }
        
        this.lightbox.classList.remove('active');
        document.body.style.overflow = '';
        this.lightboxMediaContainer.innerHTML = '';
    }

    navigate(direction) {
        const videoElement = this.lightboxMediaContainer.querySelector('video');
        if (videoElement) {
            videoElement.pause();
        }
        
        this.currentIndex = (this.currentIndex + direction + this.galleryItems.length) % this.galleryItems.length;
        this.updateLightboxContent();
        
        const newVideoElement = this.lightboxMediaContainer.querySelector('video');
        if (newVideoElement) {
            newVideoElement.play();
        }
    }

    updateLightboxContent() {
        const item = this.galleryItems[this.currentIndex];
        const type = item.dataset.type;
        const url = item.dataset.url;
        const filename = item.dataset.filename;
        
        this.lightboxMediaContainer.innerHTML = '';
        
        if (type === 'image') {
            const img = document.createElement('img');
            img.src = url;
            img.alt = filename;
            this.lightboxMediaContainer.appendChild(img);
        } else {
            const video = document.createElement('video');
            video.src = url;
            video.controls = true;
            video.autoplay = true;
            this.lightboxMediaContainer.appendChild(video);
        }
        
        this.lightboxCaption.textContent = filename;
        this.lightboxCounter.textContent = `${this.currentIndex + 1} / ${this.galleryItems.length}`;
    }

    attachItemClickListeners() {
        const items = document.querySelectorAll('.gallery-item');
        items.forEach((item, index) => {
            item.addEventListener('click', () => this.openLightbox(index));
        });
    }

    setupRefreshTimer() {
        setTimeout(() => this.refreshUrls(), 25 * 60 * 1000);
        setInterval(() => this.refreshUrls(), this.refreshInterval);
    }

    setupVisibilityHandler() {
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
                    item.dataset.url = data.url;
                }
            } catch (error) {
                console.error('Failed to refresh URL for item:', mediaId, error);
            }
        });
        
        await Promise.all(refreshPromises);
    }
}

// Initialize when the DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const gallery = new GalleryManager();
    gallery.attachItemClickListeners();
});


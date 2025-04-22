class GalleryManager {
    constructor() {
        this.refreshInterval = 30 * 60 * 1000; // 30 minutes
        this.setupRefreshTimer();
        this.setupVisibilityHandler();
        this.currentIndex = 0;
        this.items = [];
        this.setupControls();
        
        // Hide modal and controls initially
        const modal = document.getElementById('mediaModal');
        if (modal) {
            modal.style.display = 'none';
            // Hide counter and navigation initially
            const counter = modal.querySelector('.modal-counter');
            const navigation = modal.querySelector('.modal-navigation');
            if (counter) counter.style.display = 'none';
            if (navigation) navigation.style.display = 'none';
        }
    }

    setupControls() {
        const mediaTypeFilter = document.getElementById('mediaTypeFilter');
        const sortOrder = document.getElementById('sortOrder');
        
        if (mediaTypeFilter) {
            mediaTypeFilter.addEventListener('change', () => this.refreshGallery());
        }
        
        if (sortOrder) {
            sortOrder.addEventListener('change', () => this.refreshGallery());
        }
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

    openModal(index) {
        const modal = document.getElementById('mediaModal');
        const mediaContainer = modal.querySelector('.modal-media-container');
        const item = this.items[index];
        this.currentIndex = index;

        // Clear previous content
        mediaContainer.innerHTML = '';

        // Create media element
        let mediaElement;
        if (item.type === 'image') {
            mediaElement = document.createElement('img');
            mediaElement.src = item.url;
            mediaElement.alt = item.filename;
        } else {
            mediaElement = document.createElement('video');
            mediaElement.src = item.url;
            mediaElement.controls = true;
        }

        // Add media to container
        mediaContainer.appendChild(mediaElement);
        
        // Show modal and controls
        modal.style.display = 'block';
        const counter = modal.querySelector('.modal-counter');
        const navigation = modal.querySelector('.modal-navigation');
        if (counter) {
            counter.style.display = 'block';
            counter.textContent = `${index + 1} / ${this.items.length}`;
        }
        if (navigation) navigation.style.display = 'flex';
    }

    closeModal() {
        const modal = document.getElementById('mediaModal');
        if (modal) {
            modal.style.display = 'none';
            // Hide counter and navigation when closing
            const counter = modal.querySelector('.modal-counter');
            const navigation = modal.querySelector('.modal-navigation');
            if (counter) counter.style.display = 'none';
            if (navigation) counter.style.display = 'none';
        }
    }
}

// Function to attach click listeners to gallery items
function attachItemClickListeners() {
    const galleryItems = document.querySelectorAll('.gallery-item');
    const modal = document.getElementById('mediaModal');
    const closeBtn = modal.querySelector('.modal-close');
    const prevBtn = modal.querySelector('.modal-prev');
    const nextBtn = modal.querySelector('.modal-next');
    
    const gallery = new GalleryManager();
    gallery.items = Array.from(galleryItems).map(item => ({
        id: item.dataset.id,
        type: item.dataset.type,
        url: item.dataset.url,
        filename: item.dataset.filename
    }));

    galleryItems.forEach((item, index) => {
        item.addEventListener('click', () => gallery.openModal(index));
    });

    if (closeBtn) closeBtn.addEventListener('click', () => gallery.closeModal());
    if (prevBtn) prevBtn.addEventListener('click', () => {
        if (gallery.currentIndex > 0) {
            gallery.openModal(gallery.currentIndex - 1);
        }
    });
    if (nextBtn) nextBtn.addEventListener('click', () => {
        if (gallery.currentIndex < gallery.items.length - 1) {
            gallery.openModal(gallery.currentIndex + 1);
        }
    });

    window.addEventListener('click', (event) => {
        if (event.target === modal) {
            gallery.closeModal();
        }
    });
}

// Initialize when the page loads
document.addEventListener('DOMContentLoaded', () => {
    const gallery = new GalleryManager();
    attachItemClickListeners();
});





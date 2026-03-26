window.API_BASE_URL = location.hostname === 'localhost' || location.hostname === '127.0.0.1' || location.hostname.includes('onrender.com') ? '' : 'https://api.devseasglobal.com';

document.addEventListener('DOMContentLoaded', () => {
    // Mobile Menu Toggle
    const menuToggle = document.getElementById('mobile-menu');
    const navMenu = document.querySelector('.nav-menu');

    if (menuToggle && navMenu) {
        menuToggle.addEventListener('click', () => {
            navMenu.classList.toggle('active');
            const icon = menuToggle.querySelector('i');
            if (navMenu.classList.contains('active')) {
                icon.classList.remove('fa-bars');
                icon.classList.add('fa-times');
            } else {
                icon.classList.remove('fa-times');
                icon.classList.add('fa-bars');
            }
        });
    }

    // --- Theme Toggle Logic ---
    const themeToggle = document.querySelector('.theme-toggle');
    const body = document.body;
    const ICON_DARK = '<i class="fas fa-moon"></i>';
    const ICON_LIGHT = '<i class="fas fa-sun"></i>';

    // Apply saved preference immediately
    if (localStorage.getItem('theme') === 'light') {
        body.classList.add('light-mode');
        if (themeToggle) themeToggle.innerHTML = ICON_DARK;
    } else {
        if (themeToggle) themeToggle.innerHTML = ICON_LIGHT;
    }

    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            body.classList.toggle('light-mode');
            const isLight = body.classList.contains('light-mode');
            localStorage.setItem('theme', isLight ? 'light' : 'dark');
            themeToggle.innerHTML = isLight ? ICON_DARK : ICON_LIGHT;
        });
    }

    // --- Dynamic Navbar Categories Logic ---
    async function loadNavbarCategories() {
        const dynamicWrappers = document.querySelectorAll('.dropdown-categories-dynamic');
        if (dynamicWrappers.length === 0) return;

        try {
            const res = await fetch(`${window.API_BASE_URL}/api/categories`);
            if (!res.ok) throw new Error('Failed to fetch');
            const categories = await res.json();

            dynamicWrappers.forEach(wrapper => {
                // Keep the 'All Products' link, append the rest
                let html = '<a href="products.html?category=all" class="dropdown-item">All Products</a>';
                categories.forEach(cat => {
                    html += `<a href="products.html?category=${cat.slug}" class="dropdown-item">${cat.name}</a>`;
                });
                wrapper.innerHTML = html;
            });
        } catch (error) {
            console.error('Error loading navbar categories:', error);
        }
    }

    loadNavbarCategories();

    // --- Dynamic Navbar Catalogue Logic ---
    async function loadNavbarCatalogues() {
        const dynamicWrappers = document.querySelectorAll('.dropdown-catalogues-dynamic');
        if (dynamicWrappers.length === 0) return;

        try {
            const res = await fetch(`${window.API_BASE_URL}/api/catalogues`);
            if (!res.ok) throw new Error('Failed to fetch');
            const catalogues = await res.json();

            dynamicWrappers.forEach(wrapper => {
                let html = '';
                if (catalogues.length === 0) {
                    html = '<span class="dropdown-item">No catalogues available</span>';
                } else {
                    catalogues.forEach(cat => {
                        html += `<a href="${window.API_BASE_URL}/uploads/${cat.fileUrl}" class="dropdown-item" target="_blank" download="${cat.fileName}"><i class="fas fa-download" style="margin-right: 8px; font-size: 0.8em;"></i>${cat.name}</a>`;
                    });
                }
                wrapper.innerHTML = html;
            });
        } catch (error) {
            console.error('Error loading navbar catalogues:', error);
            dynamicWrappers.forEach(wrapper => {
                wrapper.innerHTML = '<span class="dropdown-item">Error loading catalogues</span>';
            });
        }
    }

    loadNavbarCatalogues();
});

// Mobile Dropdown Toggle (Global function called by onclick)
function toggleDropdown(e, link) {
    if (window.innerWidth <= 992) {
        const parent = link.parentElement;
        const dropdown = parent.querySelector('.dropdown-menu');

        // Only prevent navigation and show dropdown if a dropdown menu exists
        if (dropdown) {
            e.preventDefault();
            parent.classList.toggle('active');

            // Close other dropdowns
            document.querySelectorAll('.nav-item').forEach(item => {
                if (item !== parent) item.classList.remove('active');
            });
        }
    }
}

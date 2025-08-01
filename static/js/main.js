// Django Authentication Example - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Auto-hide alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // Add loading state to buttons on form submit
    var forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function() {
            var submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.innerHTML = '<span class="loading"></span> Loading...';
                submitBtn.disabled = true;
            }
        });
    });

    // Smooth scrolling for anchor links
    var anchorLinks = document.querySelectorAll('a[href^="#"]');
    anchorLinks.forEach(function(link) {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            var target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Add active class to current navigation item
    var currentPath = window.location.pathname;
    var navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    navLinks.forEach(function(link) {
        if (link.getAttribute('href') && currentPath.startsWith(link.getAttribute('href'))) {
            link.classList.add('active');
        }
    });

    // Copy to clipboard functionality
    var copyButtons = document.querySelectorAll('.copy-btn');
    copyButtons.forEach(function(btn) {
        btn.addEventListener('click', function() {
            var target = document.querySelector(this.getAttribute('data-target'));
            if (target) {
                navigator.clipboard.writeText(target.textContent).then(function() {
                    // Show success message
                    var originalText = btn.textContent;
                    btn.textContent = 'Copied!';
                    btn.classList.add('btn-success');
                    setTimeout(function() {
                        btn.textContent = originalText;
                        btn.classList.remove('btn-success');
                    }, 2000);
                });
            }
        });
    });

    // Form validation enhancement
    var forms = document.querySelectorAll('.needs-validation');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });

    // Dynamic table search
    var searchInputs = document.querySelectorAll('.table-search');
    searchInputs.forEach(function(input) {
        input.addEventListener('keyup', function() {
            var filter = this.value.toLowerCase();
            var table = document.querySelector(this.getAttribute('data-table'));
            if (table) {
                var rows = table.querySelectorAll('tbody tr');
                rows.forEach(function(row) {
                    var text = row.textContent.toLowerCase();
                    row.style.display = text.includes(filter) ? '' : 'none';
                });
            }
        });
    });

    // Auto-refresh functionality
    var autoRefreshElements = document.querySelectorAll('[data-auto-refresh]');
    autoRefreshElements.forEach(function(element) {
        var interval = parseInt(element.getAttribute('data-auto-refresh')) * 1000;
        var url = element.getAttribute('data-refresh-url');
        
        if (interval && url) {
            setInterval(function() {
                fetch(url)
                    .then(response => response.text())
                    .then(html => {
                        element.innerHTML = html;
                    })
                    .catch(error => {
                        console.error('Auto-refresh error:', error);
                    });
            }, interval);
        }
    });

    // Theme toggle (if implemented)
    var themeToggle = document.querySelector('#theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            document.body.classList.toggle('dark-theme');
            localStorage.setItem('theme', document.body.classList.contains('dark-theme') ? 'dark' : 'light');
        });

        // Load saved theme
        var savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark') {
            document.body.classList.add('dark-theme');
        }
    }

    // Confirmation dialogs
    var confirmButtons = document.querySelectorAll('[data-confirm]');
    confirmButtons.forEach(function(btn) {
        btn.addEventListener('click', function(e) {
            var message = this.getAttribute('data-confirm');
            if (!confirm(message)) {
                e.preventDefault();
            }
        });
    });

    // Progress bars animation
    var progressBars = document.querySelectorAll('.progress-bar');
    progressBars.forEach(function(bar) {
        var width = bar.getAttribute('data-width');
        if (width) {
            setTimeout(function() {
                bar.style.width = width + '%';
            }, 500);
        }
    });

    // Collapsible sections
    var collapseButtons = document.querySelectorAll('[data-bs-toggle="collapse"]');
    collapseButtons.forEach(function(btn) {
        btn.addEventListener('click', function() {
            var icon = this.querySelector('i');
            if (icon) {
                setTimeout(function() {
                    if (icon.classList.contains('fa-chevron-down')) {
                        icon.classList.replace('fa-chevron-down', 'fa-chevron-up');
                    } else {
                        icon.classList.replace('fa-chevron-up', 'fa-chevron-down');
                    }
                }, 150);
            }
        });
    });
});

// Utility functions
function showToast(message, type = 'info') {
    var toastContainer = document.querySelector('.toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }

    var toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;

    toastContainer.appendChild(toast);
    var bsToast = new bootstrap.Toast(toast);
    bsToast.show();

    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}

function formatDateTime(dateString) {
    var date = new Date(dateString);
    return date.toLocaleString();
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    var k = 1024;
    var sizes = ['Bytes', 'KB', 'MB', 'GB'];
    var i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// API helper functions
function apiCall(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')
        },
        credentials: 'include'
    };

    return fetch(url, { ...defaultOptions, ...options })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        });
}

function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

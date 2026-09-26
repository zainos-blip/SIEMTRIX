var API_BASE_URL = 'http://localhost:8000/api';
var API_V1_URL = 'http://localhost:8000/api/v1';
var DMZ_URL = 'https://entrap-underfed-collapse.ngrok-free.dev'; 



const ICON_SUN = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`;

const ICON_MOON = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`;

function getTheme() {
    return localStorage.getItem('theme') || 'dark';
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    
    document.querySelectorAll('.theme-toggle').forEach(btn => {
        btn.innerHTML = theme === 'dark' ? ICON_SUN : ICON_MOON;
        btn.title = theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode';
    });
}

function toggleTheme() {
    const current = getTheme();
    setTheme(current === 'dark' ? 'light' : 'dark');
}


(function initTheme() {
    const saved = getTheme();
    document.documentElement.setAttribute('data-theme', saved);
})();


async function apiFetch(url, options = {}) {
    const jwt = sessionStorage.getItem('jwt');
    const dmzToken = sessionStorage.getItem('dmz_session_token');
    
    if (!options.headers) {
        options.headers = {};
    }
    
    if (jwt) {
        options.headers['Authorization'] = `Bearer ${jwt}`;
    }
    
    if (dmzToken) {
        options.headers['X-DMZ-Session-Token'] = dmzToken;
    }
    
    if (!options.headers['Content-Type'] && !(options.body instanceof FormData)) {
        options.headers['Content-Type'] = 'application/json';
    }

    try {
        const response = await fetch(url, options);
        if (response.status === 401) {
            
            sessionStorage.clear();
            window.location.href = 'login.html';
            return null;
        }
        return response;
    } catch (error) {
        console.error('Fetch error:', error);
        throw error;
    }
}


function showToast(message, type = 'success') {
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        toastContainer.className = 'toast-container';
        document.body.appendChild(toastContainer);
    }
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    toastContainer.appendChild(toast);
    
    
    setTimeout(() => toast.classList.add('show'), 10);
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function logout() {
    sessionStorage.clear();
    window.location.href = 'login.html';
}

function getDmzSessionToken() {
    return sessionStorage.getItem('dmz_session_token');
}


window.addEventListener('DOMContentLoaded', () => {
    if (!sessionStorage.getItem('authenticated') && !window.location.pathname.endsWith('login.html')) {
        window.location.href = 'login.html';
    }
    
    setTheme(getTheme());
});

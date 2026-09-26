function checkAuth() {
    if (!sessionStorage.getItem('authenticated')) {
        window.location.href = 'login.html';
    }
}

function logout() {
    sessionStorage.removeItem('authenticated');
    sessionStorage.removeItem('username');
    window.location.href = 'login.html';
}


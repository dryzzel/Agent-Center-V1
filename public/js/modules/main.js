import { state } from './state.js';
import { setupSocketListeners } from './socket.js';
import { showScreen, toggleDarkMode, initTheme } from './utils.js';
import { initializeAdminHub } from './admin.js';
import { initializeApp } from './agent.js';
import { login } from './auth.js';

// Setup global listeners that don't depend on role
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    setupSocketListeners();

    const themeBtn = document.getElementById('themeToggleBtn');
    if (themeBtn) themeBtn.addEventListener('click', toggleDarkMode);

    // Login Screen Logic
    const loginBtn = document.getElementById('loginBtn');
    if (loginBtn) {
        loginBtn.addEventListener('click', handleLoginAttempt);
        document.getElementById('password')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') handleLoginAttempt();
        });
    }

    checkExistingSession();

    // Feather icons
    if (window.feather) feather.replace();

    // === Security Hardening ===
    // Disable Context Menu
    document.addEventListener('contextmenu', event => event.preventDefault());

    // Disable Shortcuts (F12, Ctrl+Shift+I, Ctrl+U, Ctrl+S)
    document.addEventListener('keydown', (e) => {
        if (
            e.key === 'F12' ||
            (e.ctrlKey && e.shiftKey && e.key === 'I') ||
            (e.ctrlKey && e.shiftKey && e.key === 'J') ||
            (e.ctrlKey && e.key === 'u')
        ) {
            e.preventDefault();
        }
    });
});

async function handleLoginAttempt() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const loginError = document.getElementById('loginError');

    if (!username || !password) {
        if (loginError) {
            loginError.textContent = 'Please fill all fields';
            loginError.style.display = 'block';
        }
        return;
    }

    const result = await login(username, password);
    if (result.success) {
        if (loginError) loginError.style.display = 'none';
        routeUser(state.currentUser);
    } else {
        if (loginError) {
            loginError.textContent = result.error || 'Invalid credentials';
            loginError.style.display = 'block';
        }
    }
}

function checkExistingSession() {
    const savedToken = localStorage.getItem('userToken');
    const savedUser = localStorage.getItem('currentUser');
    if (savedToken && savedUser) {
        state.currentUser = JSON.parse(savedUser);
        state.userToken = savedToken;
        routeUser(state.currentUser);
    } else {
        showScreen('loginScreen');
    }
}

function routeUser(user) {
    if (user.role === 'admin') {
        showScreen('adminScreen');
        initializeAdminHub();
    } else {
        showScreen('appScreen');
        initializeApp();
    }
}

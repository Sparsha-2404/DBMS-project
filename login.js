// FILE: public/js/login.js

document.addEventListener('DOMContentLoaded', function() {
    // Check for error parameter in URL
    const urlParams = new URLSearchParams(window.location.search);
    const error = urlParams.get('error');
    
    if (error) {
        const errorMessage = document.getElementById('error-message');
        errorMessage.textContent = 'Invalid username or password. Please try again.';
    }
    
    // Form validation
    const loginForm = document.querySelector('form');
    loginForm.addEventListener('submit', function(e) {
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
        
        if (!username || !password) {
            e.preventDefault();
            const errorMessage = document.getElementById('error-message');
            errorMessage.textContent = 'Please enter both username and password.';
        }
    });
});
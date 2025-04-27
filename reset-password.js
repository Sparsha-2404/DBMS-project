// FILE: public/js/reset-password.js

document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form');
    const message = document.getElementById('message');
    
    // Get token from URL and set it in the hidden field
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    
    if (!token) {
        message.textContent = 'Invalid or expired password reset link.';
        message.className = 'error-message';
        form.style.display = 'none';
        return;
    }
    
    document.getElementById('token').value = token;
    
    // Handle form submission
    form.addEventListener('submit', function(e) {
        const password = document.getElementById('password').value.trim();
        const confirmPassword = document.getElementById('confirmPassword').value.trim();
        
        if (!password || !confirmPassword) {
            e.preventDefault();
            message.textContent = 'Please fill in all fields.';
            message.className = 'error-message';
            return;
        }
        
        if (password.length < 8) {
            e.preventDefault();
            message.textContent = 'Password must be at least 8 characters.';
            message.className = 'error-message';
            return;
        }
        
        if (password !== confirmPassword) {
            e.preventDefault();
            message.textContent = 'Passwords do not match.';
            message.className = 'error-message';
            return;
        }
    });
    
    // Check for errors
    const error = urlParams.get('error');
    if (error === 'invalid') {
        message.textContent = 'Invalid or expired reset token.';
        message.className = 'error-message';
    } else if (error === 'server') {
        message.textContent = 'An error occurred. Please try again later.';
        message.className = 'error-message';
    }
});
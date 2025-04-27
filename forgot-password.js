// FILE: public/js/forgot-password.js

document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form');
    const message = document.getElementById('message');
    
    // Check for any URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const sent = urlParams.get('sent');
    const error = urlParams.get('error');
    
    if (sent === 'true') {
        message.textContent = 'If an account exists with that email, a password reset link has been sent.';
        message.className = 'success-message';
    } else if (error) {
        message.textContent = 'An error occurred. Please try again later.';
        message.className = 'error-message';
    }
    
    form.addEventListener('submit', function(e) {
        const email = document.getElementById('email').value.trim();
        
        if (!email) {
            e.preventDefault();
            message.textContent = 'Please enter your email address.';
            message.className = 'error-message';
            return;
        }
        
        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            e.preventDefault();
            message.textContent = 'Please enter a valid email address.';
            message.className = 'error-message';
            return;
        }
    });
});
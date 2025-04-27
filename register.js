// FILE: public/js/register.js

document.addEventListener('DOMContentLoaded', function() {
    const registerForm = document.querySelector('form');
    const errorMessage = document.getElementById('error-message');
    
    registerForm.addEventListener('submit', function(e) {
        // Reset error message
        errorMessage.textContent = '';
        
        // Get form fields
        const firstName = document.getElementById('firstName').value.trim();
        const lastName = document.getElementById('lastName').value.trim();
        const email = document.getElementById('email').value.trim();
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
        const confirmPassword = document.getElementById('confirmPassword').value.trim();
        
        // Validate form
        if (!firstName || !lastName || !email || !username || !password || !confirmPassword) {
            e.preventDefault();
            errorMessage.textContent = 'Please fill in all fields.';
            return;
        }
        
        // Check email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            e.preventDefault();
            errorMessage.textContent = 'Please enter a valid email address.';
            return;
        }
        
        // Check username length
        if (username.length < 4) {
            e.preventDefault();
            errorMessage.textContent = 'Username must be at least 4 characters.';
            return;
        }
        
        // Check password length
        if (password.length < 8) {
            e.preventDefault();
            errorMessage.textContent = 'Password must be at least 8 characters.';
            return;
        }
        
        // Check if passwords match
        if (password !== confirmPassword) {
            e.preventDefault();
            errorMessage.textContent = 'Passwords do not match.';
            return;
        }
    });
    
    // Check for error parameter in URL
    const urlParams = new URLSearchParams(window.location.search);
    const error = urlParams.get('error');
    
    if (error === 'username') {
        errorMessage.textContent = 'Username already exists. Please choose a different one.';
    } else if (error === 'email') {
        errorMessage.textContent = 'Email already registered. Please use a different email.';
    }
});
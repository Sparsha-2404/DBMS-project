// FILE: public/js/profile.js

document.addEventListener('DOMContentLoaded', function() {
    // Get user profile data
    fetch('/api/profile')
        .then(response => {
            if (!response.ok) {
                throw new Error('Not authenticated');
            }
            return response.json();
        })
        .then(user => {
            // Display user information in the header
            document.getElementById('header-username').textContent = user.username;
            
            // Populate profile information
            document.getElementById('profile-name').textContent = `${user.first_name} ${user.last_name}`;
            document.getElementById('profile-role').textContent = capitalizeFirstLetter(user.role);
            
            const createdDate = new Date(user.created_at);
            document.getElementById('profile-member-since').textContent = `Member since: ${createdDate.toLocaleDateString()}`;
            
            // Populate form fields
            document.getElementById('firstName').value = user.first_name;
            document.getElementById('lastName').value = user.last_name;
            document.getElementById('email').value = user.email;
            document.getElementById('username').value = user.username;
            
            // Populate session info
            if (user.last_login) {
                const lastLogin = new Date(user.last_login);
                document.getElementById('last-login').textContent = lastLogin.toLocaleString();
            }
            
            if (user.ip_address) {
                document.getElementById('ip-address').textContent = user.ip_address;
            }
            
            document.getElementById('browser').textContent = getBrowserInfo();
        })
        .catch(error => {
            console.error('Error fetching profile:', error);
            // Redirect to login if not authenticated
            if (error.message === 'Not authenticated') {
                window.location.href = '/login';
            }
        });
    
    // Handle profile form submission
    const profileForm = document.getElementById('profile-form');
    profileForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const firstName = document.getElementById('firstName').value.trim();
        const lastName = document.getElementById('lastName').value.trim();
        const email = document.getElementById('email').value.trim();
        
        // Basic validation
        if (!firstName || !lastName || !email) {
            showMessage('Please fill in all fields.', 'error');
            return;
        }
        
        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            showMessage('Please enter a valid email address.', 'error');
            return;
        }
        
        // Submit data to server
        fetch('/api/update-profile', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                firstName,
                lastName,
                email
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showMessage('Profile updated successfully!', 'success');
                
                // Update displayed name
                document.getElementById('profile-name').textContent = `${firstName} ${lastName}`;
            } else {
                showMessage(data.message || 'An error occurred.', 'error');
            }
        })
        .catch(error => {
            console.error('Error updating profile:', error);
            showMessage('An error occurred. Please try again.', 'error');
        });
    });
    
    // Handle password form submission
    const passwordForm = document.getElementById('password-form');
    passwordForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const currentPassword = document.getElementById('currentPassword').value.trim();
        const newPassword = document.getElementById('newPassword').value.trim();
        const confirmPassword = document.getElementById('confirmPassword').value.trim();
        
        // Basic validation
        if (!currentPassword || !newPassword || !confirmPassword) {
            showMessage('Please fill in all password fields.', 'error');
            return;
        }
        
        // Password length validation
        if (newPassword.length < 8) {
            showMessage('New password must be at least 8 characters.', 'error');
            return;
        }
        
        // Password match validation
        if (newPassword !== confirmPassword) {
            showMessage('New passwords do not match.', 'error');
            return;
        }
        
        // Submit data to server
        fetch('/api/change-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                currentPassword,
                newPassword
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showMessage('Password changed successfully!', 'success');
                
                // Clear password fields
                document.getElementById('currentPassword').value = '';
                document.getElementById('newPassword').value = '';
                document.getElementById('confirmPassword').value = '';
            } else {
                showMessage(data.message || 'An error occurred.', 'error');
            }
        })
        .catch(error => {
            console.error('Error changing password:', error);
            showMessage('An error occurred. Please try again.', 'error');
        });
    });
    
    // Panel navigation (same as in dashboard.js)
    const navLinks = document.querySelectorAll('.nav-links li');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function() {
            if (this.classList.contains('logout')) {
                window.location.href = '/logout';
                return;
            }
            
            const targetPanel = this.getAttribute('data-panel');
            
            if (targetPanel === 'dashboard') {
                window.location.href = '/dashboard';
                return;
            }
        });
    });
    
    // Helper functions
    function showMessage(message, type) {
        const messageContainer = document.getElementById('profile-message');
        messageContainer.textContent = message;
        messageContainer.className = `message-container ${type}`;
        
        // Clear message after 5 seconds
        setTimeout(() => {
            messageContainer.textContent = '';
            messageContainer.className = 'message-container';
        }, 5000);
    }
    
    function capitalizeFirstLetter(string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    }
    
    function getBrowserInfo() {
        const userAgent = navigator.userAgent;
        let browserName;
        
        if (userAgent.match(/chrome|chromium|crios/i)) {
            browserName = "Chrome";
        } else if (userAgent.match(/firefox|fxios/i)) {
            browserName = "Firefox";
        } else if (userAgent.match(/safari/i)) {
            browserName = "Safari";
        } else if (userAgent.match(/opr\//i)) {
            browserName = "Opera";
        } else if (userAgent.match(/edg/i)) {
            browserName = "Edge";
        } else {
            browserName = "Unknown";
        }
        
        return `${browserName} on ${navigator.platform}`;
    }
});
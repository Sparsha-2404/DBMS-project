// FILE: public/js/dashboard.js

document.addEventListener('DOMContentLoaded', function() {
    // Panel navigation
    const navLinks = document.querySelectorAll('.nav-links li');
    const panels = document.querySelectorAll('.panel');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function() {
            const targetPanel = this.getAttribute('data-panel');
            
            // Handle logout
            if (this.classList.contains('logout')) {
                window.location.href = '/logout';
                return;
            }
            
            // Update active class
            navLinks.forEach(item => item.classList.remove('active'));
            this.classList.add('active');
            
            // Show target panel
            panels.forEach(panel => panel.classList.remove('active'));
            document.getElementById(`${targetPanel}-panel`).classList.add('active');
            
            // Load data for the panel
            loadPanelData(targetPanel);
        });
    });
    
    // Initialize dashboard
    loadDashboardSummary();
    loadCharts();
    loadRecentAlerts();
    
    // Setup event listeners for filter buttons
    document.getElementById('apply-alert-filters')?.addEventListener('click', () => loadPanelData('alerts'));
    document.getElementById('apply-tx-filters')?.addEventListener('click', () => loadPanelData('transactions'));
    
    // Modal setup
    const modal = document.getElementById('alert-modal');
    const closeModal = document.querySelector('.close-modal');
    
    if (closeModal) {
        closeModal.addEventListener('click', () => {
            modal.style.display = 'none';
        });
    }
    
    // Close modal if clicking outside of it
    window.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
        }
    });
    
    // Resolve alert button
    document.getElementById('resolve-alert-btn')?.addEventListener('click', resolveAlert);
});

function loadPanelData(panelType) {
    switch(panelType) {
        case 'alerts':
            loadAlerts();
            break;
        case 'transactions':
            loadTransactions();
            break;
        case 'high-risk':
            loadHighRiskAccounts();
            break;
        case 'logins':
            loadSuspiciousLogins();
            break;
    }
}

function loadDashboardSummary() {
    // Fetch summary data for dashboard statistics
    fetch('/api/alerts')
        .then(response => response.json())
        .then(data => {
            const openAlerts = data.filter(alert => alert.alert_status !== 'Closed').length;
            document.getElementById('open-alerts').textContent = openAlerts;
        })
        .catch(error => console.error('Error loading alerts:', error));
    
    fetch('/api/high-risk-accounts')
        .then(response => response.json())
        .then(data => {
            document.getElementById('high-risk-count').textContent = data.length;
        })
        .catch(error => console.error('Error loading high risk accounts:', error));
    
    fetch('/api/suspicious-login-attempts')
        .then(response => response.json())
        .then(data => {
            // Filter for last 24 hours
            const oneDayAgo = new Date();
            oneDayAgo.setDate(oneDayAgo.getDate() - 1);
            
            const recentFailures = data.filter(login => {
                const loginDate = new Date(login.login_date);
                return loginDate > oneDayAgo;
            }).length;
            
            document.getElementById('failed-logins').textContent = recentFailures;
        })
        .catch(error => console.error('Error loading login attempts:', error));
    
    fetch('/api/transactions')
        .then(response => response.json())
        .then(data => {
            const suspendedTx = data.filter(tx => tx.transaction_status === 'Suspended').length;
            document.getElementById('suspended-tx').textContent = suspendedTx;
        })
        .catch(error => console.error('Error loading transactions:', error));
}

function loadCharts() {
    // Create Alert Types chart
    fetch('/api/alerts')
        .then(response => response.json())
        .then(data => {
            const alertTypes = {};
            data.forEach(alert => {
                if (alertTypes[alert.alert_type]) {
                    alertTypes[alert.alert_type]++;
                } else {
                    alertTypes[alert.alert_type] = 1;
                }
            });
            
            const ctx = document.getElementById('alertTypesChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: Object.keys(alertTypes),
                    datasets: [{
                        data: Object.values(alertTypes),
                        backgroundColor: [
                            '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom',
                        },
                        title: {
                            display: true,
                            text: 'Alert Types Distribution'
                        }
                    }
                }
            });
        })
        .catch(error => console.error('Error creating alert types chart:', error));
    
    // Create Risk Distribution chart
    fetch('/api/high-risk-accounts')
        .then(response => response.json())
        .then(data => {
            // Group accounts by risk score ranges
            const riskRanges = {
                '90-100': 0,
                '80-89': 0,
                '70-79': 0
            };
            
            data.forEach(account => {
                const score = account.risk_score;
                if (score >= 90) {
                    riskRanges['90-100']++;
                } else if (score >= 80) {
                    riskRanges['80-89']++;
                } else if (score >= 70) {
                    riskRanges['70-79']++;
                }
            });
            
            const ctx = document.getElementById('riskDistributionChart').getContext('2d');
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: Object.keys(riskRanges),
                    datasets: [{
                        label: 'Number of Accounts',
                        data: Object.values(riskRanges),
                        backgroundColor: '#36A2EB'
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            display: false
                        },
                        title: {
                            display: true,
                            text: 'Risk Score Distribution'
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Number of Accounts'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Risk Score Range'
                            }
                        }
                    }
                }
            });
        })
        .catch(error => console.error('Error creating risk distribution chart:', error));
}

function loadRecentAlerts() {
    fetch('/api/alerts')
        .then(response => response.json())
        .then(data => {
            // Filter for high priority alerts
            const highPriorityAlerts = data.filter(alert => alert.alert_priority === 'High');
            
            // Sort by date (newest first)
            highPriorityAlerts.sort((a, b) => new Date(b.alert_date) - new Date(a.alert_date));
            
            // Take only the top 10
            const recentAlerts = highPriorityAlerts.slice(0, 10);
            
            const tableBody = document.querySelector('#recent-alerts-table tbody');
            tableBody.innerHTML = '';
            
            recentAlerts.forEach(alert => {
                const row = document.createElement('tr');
                
                // Determine status class for coloring
                let statusClass = '';
                if (alert.alert_status === 'Open') statusClass = 'status-open';
                else if (alert.alert_status === 'Investigating') statusClass = 'status-investigating';
                else if (alert.alert_status === 'Closed') statusClass = 'status-closed';
                
                // Create row content
                row.innerHTML = `
                    <td>${alert.alert_id}</td>
                    <td>${alert.alert_type}</td>
                    <td>${alert.first_name} ${alert.last_name}</td>
                    <td>${new Date(alert.alert_date).toLocaleDateString()}</td>
                    <td class="priority-high">${alert.alert_priority}</td>
                    <td class="${statusClass}">${alert.alert_status}</td>
                    <td><button class="btn-view" data-id="${alert.alert_id}">View</button></td>
                `;
                
                tableBody.appendChild(row);
            });
            
            // Add event listeners to view buttons
            document.querySelectorAll('.btn-view').forEach(button => {
                button.addEventListener('click', function() {
                    const alertId = this.getAttribute('data-id');
                    showAlertDetails(alertId, data);
                });
            });
        })
        .catch(error => console.error('Error loading recent alerts:', error));
}

function loadAlerts() {
    const statusFilter = document.getElementById('alert-status-filter').value;
    const priorityFilter = document.getElementById('alert-priority-filter').value;
    
    fetch('/api/alerts')
        .then(response => response.json())
        .then(data => {
            // Apply filters
            let filteredData = data;
            
            if (statusFilter !== 'all') {
                filteredData = filteredData.filter(alert => alert.alert_status === statusFilter);
            }
            
            if (priorityFilter !== 'all') {
                filteredData = filteredData.filter(alert => alert.alert_priority === priorityFilter);
            }
            
            // Sort by date (newest first)
            filteredData.sort((a, b) => new Date(b.alert_date) - new Date(a.alert_date));
            
            const tableBody = document.querySelector('#alerts-table tbody');
            tableBody.innerHTML = '';
            
            filteredData.forEach(alert => {
                const row = document.createElement('tr');
                
                // Determine status and priority classes for coloring
                let statusClass = '';
                if (alert.alert_status === 'Open') statusClass = 'status-open';
                else if (alert.alert_status === 'Investigating') statusClass = 'status-investigating';
                else if (alert.alert_status === 'Closed') statusClass = 'status-closed';
                
                let priorityClass = '';
                if (alert.alert_priority === 'High') priorityClass = 'priority-high';
                else if (alert.alert_priority === 'Medium') priorityClass = 'priority-medium';
                else if (alert.alert_priority === 'Low') priorityClass = 'priority-low';
                
                // Format amount with currency symbol
                const amount = new Intl.NumberFormat('en-US', {
                    style: 'currency',
                    currency: 'USD'
                }).format(alert.amount);
                
                // Create row content
                row.innerHTML = `
                    <td>${alert.alert_id}</td>
                    <td>${alert.alert_type}</td>
                    <td>${alert.first_name} ${alert.last_name}</td>
                    <td>${amount}</td>
                    <td>${new Date(alert.alert_date).toLocaleDateString()}</td>
                    <td class="${priorityClass}">${alert.alert_priority}</td>
                    <td class="${statusClass}">${alert.alert_status}</td>
                    <td>
                        <button class="btn-view" data-id="${alert.alert_id}">View</button>
                        ${alert.alert_status !== 'Closed' ? `<button class="btn-resolve" data-id="${alert.alert_id}">Resolve</button>` : ''}
                    </td>
                `;
                
                tableBody.appendChild(row);
            });
            
            // Add event listeners to buttons
            document.querySelectorAll('#alerts-table .btn-view').forEach(button => {
                button.addEventListener('click', function() {
                    const alertId = this.getAttribute('data-id');
                    showAlertDetails(alertId, data);
                });
            });
            
            document.querySelectorAll('#alerts-table .btn-resolve').forEach(button => {
                button.addEventListener('click', function() {
                    const alertId = this.getAttribute('data-id');
                    showAlertDetails(alertId, data, true);
                });
            });
        })
        .catch(error => console.error('Error loading alerts:', error));
}

function loadTransactions() {
    const typeFilter = document.getElementById('tx-type-filter').value;
    const statusFilter = document.getElementById('tx-status-filter').value;
    
    fetch('/api/transactions')
        .then(response => response.json())
        .then(data => {
            // Apply filters
            let filteredData = data;
            
            if (typeFilter !== 'all') {
                filteredData = filteredData.filter(tx => tx.transaction_type === typeFilter);
            }
            
            if (statusFilter !== 'all') {
                filteredData = filteredData.filter(tx => tx.transaction_status === statusFilter);
            }
            
            // Sort by date (newest first)
            filteredData.sort((a, b) => new Date(b.transaction_date) - new Date(a.transaction_date));
            
            const tableBody = document.querySelector('#transactions-table tbody');
            tableBody.innerHTML = '';
            
            filteredData.forEach(tx => {
                const row = document.createElement('tr');
                
                // Determine status class for coloring
                let statusClass = '';
                if (tx.transaction_status === 'Completed') statusClass = 'status-completed';
                else if (tx.transaction_status === 'Pending') statusClass = 'status-pending';
                else if (tx.transaction_status === 'Failed') statusClass = 'status-failed';
                else if (tx.transaction_status === 'Suspended') statusClass = 'status-suspended';
                
                // Format amount with currency symbol
                const amount = new Intl.NumberFormat('en-US', {
                    style: 'currency',
                    currency: 'USD'
                }).format(tx.amount);
                
                // Create row content
                row.innerHTML = `
                    <td>${tx.transaction_id}</td>
                    <td>${tx.first_name} ${tx.last_name}</td>
                    <td>${tx.transaction_type}</td>
                    <td>${amount}</td>
                    <td>${new Date(tx.transaction_date).toLocaleDateString()}</td>
                    <td class="${statusClass}">${tx.transaction_status}</td>
                    <td>
                        <button class="btn-details">Details</button>
                    </td>
                `;
                
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading transactions:', error));
}

function loadHighRiskAccounts() {
    fetch('/api/high-risk-accounts')
        .then(response => response.json())
        .then(data => {
            // Sort by risk score (highest first)
            data.sort((a, b) => b.risk_score - a.risk_score);
            
            const tableBody = document.querySelector('#high-risk-table tbody');
            tableBody.innerHTML = '';
            
            data.forEach(account => {
                const row = document.createElement('tr');
                
                // Determine risk class for coloring
                let riskClass = '';
                if (account.risk_score >= 90) riskClass = 'risk-critical';
                else if (account.risk_score >= 80) riskClass = 'risk-high';
                else riskClass = 'risk-elevated';
                
                // Format balance with currency symbol
                const balance = new Intl.NumberFormat('en-US', {
                    style: 'currency',
                    currency: 'USD'
                }).format(account.balance);
                
                // Create row content
                row.innerHTML = `
                    <td>${account.account_id}</td>
                    <td>${account.first_name} ${account.last_name}</td>
                    <td>${account.account_type}</td>
                    <td>${balance}</td>
                    <td class="${riskClass}">${account.risk_score}</td>
                    <td>
                        <button class="btn-details">View Activity</button>
                        <button class="btn-flag">Flag Account</button>
                    </td>
                `;
                
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading high risk accounts:', error));
}

function loadSuspiciousLogins() {
    fetch('/api/suspicious-login-attempts')
        .then(response => response.json())
        .then(data => {
            // Sort by date (newest first)
            data.sort((a, b) => new Date(b.login_date) - new Date(a.login_date));
            
            const tableBody = document.querySelector('#logins-table tbody');
            tableBody.innerHTML = '';
            
            data.forEach(login => {
                const row = document.createElement('tr');
                
                // Create row content
                row.innerHTML = `
                    <td>${login.login_id}</td>
                    <td>${login.first_name} ${login.last_name}</td>
                    <td>${new Date(login.login_date).toLocaleString()}</td>
                    <td class="status-failed">${login.login_status}</td>
                    <td>${login.latitude.toFixed(6)}, ${login.longitude.toFixed(6)}</td>
                    <td>
                        <button class="btn-map">View Map</button>
                        <button class="btn-notify">Notify User</button>
                    </td>
                `;
                
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading suspicious logins:', error));
}

function showAlertDetails(alertId, alertsData, showResolutionForm = false) {
    const alert = alertsData.find(a => a.alert_id == alertId);
    
    if (!alert) {
        console.error('Alert not found');
        return;
    }
    
    // Format amount and date
    const amount = new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
    }).format(alert.amount);
    
    const date = new Date(alert.alert_date).toLocaleString();
    
    // Populate modal with alert details
    document.getElementById('modal-alert-id').textContent = alert.alert_id;
    document.getElementById('modal-alert-type').textContent = alert.alert_type;
    document.getElementById('modal-customer').textContent = `${alert.first_name} ${alert.last_name}`;
    document.getElementById('modal-transaction').textContent = alert.transaction_type;
    document.getElementById('modal-amount').textContent = amount;
    document.getElementById('modal-date').textContent = date;
    document.getElementById('modal-status').textContent = alert.alert_status;
    document.getElementById('modal-priority').textContent = alert.alert_priority;
    document.getElementById('modal-message').textContent = alert.alert_message;
    
    // Show/hide resolution form based on alert status and parameter
    const resolutionForm = document.getElementById('resolution-form');
    if (showResolutionForm && alert.alert_status !== 'Closed') {
        resolutionForm.style.display = 'block';
        
        // Set alert ID as data attribute on resolve button
        const resolveBtn = document.getElementById('resolve-alert-btn');
        resolveBtn.setAttribute('data-alert-id', alert.alert_id);
    } else {
        resolutionForm.style.display = 'none';
    }
    
    // Show modal
    document.getElementById('alert-modal').style.display = 'block';
}

function resolveAlert() {
    const alertId = document.getElementById('resolve-alert-btn').getAttribute('data-alert-id');
    const resolution = document.getElementById('resolution').value;
    const resolvedBy = 'Admin User'; // In a real app, get this from the logged-in user
    
    // Send resolution to server
    fetch('/api/resolve-alert', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ alertId, resolution, resolvedBy })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Close modal
            document.getElementById('alert-modal').style.display = 'none';
            
            // Reload current panel data to reflect changes
            const activePanel = document.querySelector('.nav-links li.active').getAttribute('data-panel');
            loadPanelData(activePanel);
            
            // Also reload dashboard summary if visible
            if (activePanel === 'dashboard') {
                loadDashboardSummary();
                loadRecentAlerts();
            }
            
            alert('Alert successfully resolved.');
        } else {
            alert('Error resolving alert. Please try again.');
        }
    })
    .catch(error => {
        console.error('Error resolving alert:', error);
        alert('Error resolving alert. Please try again.');
    });
}

// Already existing code above stays...

function loadPanelData(panelType) {
    switch(panelType) {
        case 'alerts':
            loadAlerts();
            break;
        case 'transactions':
            loadTransactions();
            break;
        case 'high-risk':
            loadHighRiskAccounts();
            break;
        case 'logins':
            loadSuspiciousLogins();
            break;
        case 'customers':
            loadCustomers();
            break;
        case 'accounts':
            loadAccounts();
            break;
        case 'devices':
            loadDevices();
            break;
        case 'banks':
            loadBanks();
            break;
        case 'risk-levels':
            loadRiskLevels();
            break;
    }
}

// New Functions:

function loadCustomers() {
    fetch('/api/customers')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.querySelector('#customers-table tbody');
            tableBody.innerHTML = '';
            data.forEach(customer => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${customer.customer_id}</td>
                    <td>${customer.first_name} ${customer.last_name}</td>
                    <td>${customer.email}</td>
                    <td>${customer.phone_number}</td>
                    <td>${customer.profession}</td>
                    <td>${new Date(customer.customer_since).toLocaleDateString()}</td>
                    <td><button class="btn-details">View</button></td>
                `;
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading customers:', error));
}

function loadAccounts() {
    fetch('/api/accounts')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.querySelector('#accounts-table tbody');
            tableBody.innerHTML = '';
            data.forEach(account => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${account.account_id}</td>
                    <td>${account.first_name} ${account.last_name}</td>
                    <td>${account.account_type}</td>
                    <td>${account.balance.toFixed(2)}</td>
                    <td>${account.account_status}</td>
                    <td>${account.risk_score !== null ? account.risk_score : 'N/A'}</td>
                    <td><button class="btn-details">View</button></td>
                `;
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading accounts:', error));
}

function loadDevices() {
    fetch('/api/devices')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.querySelector('#devices-table tbody');
            tableBody.innerHTML = '';
            data.forEach(device => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${device.device_id}</td>
                    <td>${device.first_name} ${device.last_name}</td>
                    <td>${device.device_type}</td>
                    <td>${device.device_os}</td>
                    <td>${device.ip_address}</td>
                    <td>${new Date(device.first_used).toLocaleString()}</td>
                    <td>${new Date(device.last_used).toLocaleString()}</td>
                `;
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading devices:', error));
}

function loadBanks() {
    fetch('/api/banks')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.querySelector('#banks-table tbody');
            tableBody.innerHTML = '';
            data.forEach(bank => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${bank.bank_id}</td>
                    <td>${bank.bank_name}</td>
                    <td>${bank.bank_code}</td>
                    <td>${bank.bank_address}</td>
                    <td>${bank.transaction_count}</td>
                `;
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading banks:', error));
}

function loadRiskLevels() {
    fetch('/api/risk-levels')
        .then(response => response.json())
        .then(data => {
            const tableBody = document.querySelector('#risk-levels-table tbody');
            tableBody.innerHTML = '';
            data.forEach(risk => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${risk.account_id}</td>
                    <td>${risk.risk_score}</td>
                    <td>${risk.device_type ? risk.device_type + ' (' + risk.device_os + ')' : 'N/A'}</td>
                    <td>${new Date(risk.last_assessment_date).toLocaleString()}</td>
                `;
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error loading risk levels:', error));
}

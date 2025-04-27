// FILE: server.js
const express = require('express');
const mysql = require('mysql2');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt'); // For password hashing
const crypto = require('crypto'); // For generating reset tokens
const nodemailer = require('nodemailer'); // For sending emails

// Create Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware setup - should come BEFORE route definitions
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'fraud-detection-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: false, // Set to true if using https
    maxAge: 3600000 // Session timeout: 1 hour
  }
}));

// Database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Sparsha@2006',
  database: 'Frauddetection'
});

// Connect to database
db.connect((err) => {
  if (err) {
    console.error('Error connecting to database:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

// Simple authentication middleware
const authenticateUser = (req, res, next) => {
  if (req.session.authenticated && req.session.userId) {
    // Check if session has expired
    if (req.session.cookie.expires && new Date() > req.session.cookie.expires) {
      req.session.destroy();
      return res.redirect('/login?session=expired');
    }
    
    // Refresh session timeout
    req.session.cookie.expires = new Date(Date.now() + 3600000);
    next();
  } else {
    res.redirect('/login');
  }
};

// Store user IP and update last login
const trackUserActivity = (userId, req) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  
  const query = `
    UPDATE Users
    SET last_login = NOW(), last_ip = ?
    WHERE user_id = ?
  `;
  
  db.query(query, [ip, userId], (err) => {
    if (err) {
      console.error('Error updating user activity:', err);
    }
  });
};

// Routes
app.get('/', (req, res) => {
  if (req.session.authenticated) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

// Login routes
app.get('/login', (req, res) => {
  if (req.session.authenticated) {
    return res.redirect('/dashboard');
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/login.html', (req, res) => {
  res.redirect('/login');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Check credentials against database (with bcrypt for secure apps)
  const query = 'SELECT * FROM Users WHERE username = ?';
  
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error('Database error during login:', err);
      return res.redirect('/login?error=1');
    }
    
    if (results.length === 0) {
      return res.redirect('/login?error=1');
    }
    
    const user = results[0];
    
    // For development/testing (REPLACE WITH BCRYPT IN PRODUCTION)
    if (username === 'admin' && password === 'password') {
      req.session.authenticated = true;
      req.session.userId = user.user_id;
      req.session.username = user.username;
      req.session.role = user.role;
      
      // Track login activity
      trackUserActivity(user.user_id, req);
      
      return res.redirect('/dashboard');
    }
    
    // For production (uncomment when using bcrypt)
    /*
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.redirect('/login?error=1');
      }
      
      req.session.authenticated = true;
      req.session.userId = user.user_id;
      req.session.username = user.username;
      req.session.role = user.role;
      
      // Track login activity
      trackUserActivity(user.user_id, req);
      
      res.redirect('/dashboard');
    });
    */
    
    // For now, without bcrypt:
    if (password === user.password) {
      req.session.authenticated = true;
      req.session.userId = user.user_id;
      req.session.username = user.username;
      req.session.role = user.role;
      
      // Track login activity
      trackUserActivity(user.user_id, req);
      
      res.redirect('/dashboard');
    } else {
      res.redirect('/login?error=1');
    }
  });
});

// Registration routes
app.get('/register', (req, res) => {
  if (req.session.authenticated) {
    return res.redirect('/dashboard');
  }
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', (req, res) => {
  const { firstName, lastName, email, username, password, confirmPassword, role } = req.body;
  
  // Validate passwords match
  if (password !== confirmPassword) {
    return res.redirect('/register?error=password');
  }
  
  // Check if username already exists
  db.query('SELECT * FROM Users WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.redirect('/register?error=server');
    }
    
    if (results.length > 0) {
      return res.redirect('/register?error=username');
    }
    
    // Check if email already exists
    db.query('SELECT * FROM Users WHERE email = ?', [email], (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.redirect('/register?error=server');
      }
      
      if (results.length > 0) {
        return res.redirect('/register?error=email');
      }
      
      // In a production environment, hash the password
      // For example: const hashedPassword = bcrypt.hashSync(password, 10);
      
      // For now, without bcrypt:
      const hashedPassword = password;
      
      // Insert new user
      const query = `
        INSERT INTO Users (first_name, last_name, email, username, password, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?, NOW())
      `;
      
      const userRole = role || 'analyst'; // Default role
      
      db.query(query, [firstName, lastName, email, username, hashedPassword, userRole], (err, results) => {
        if (err) {
          console.error('Error registering user:', err);
          return res.redirect('/register?error=server');
        }
        
        // Redirect to login page with success message
        res.redirect('/login?registered=1');
      });
    });
  });
});

// Password reset routes
app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  
  // Check if email exists
  db.query('SELECT * FROM Users WHERE email = ?', [email], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.redirect('/forgot-password?error=server');
    }
    
    // Always return success even if email not found (security best practice)
    if (results.length === 0) {
      return res.redirect('/forgot-password?sent=true');
    }
    
    const user = results[0];
    
    // Generate reset token
    const token = crypto.randomBytes(20).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hour expiration
    
    // Store token in database
    const query = `
      INSERT INTO PasswordResets (user_id, token, expires_at)
      VALUES (?, ?, ?)
    `;
    
    db.query(query, [user.user_id, token, expires], (err) => {
      if (err) {
        console.error('Error storing reset token:', err);
        return res.redirect('/forgot-password?error=server');
      }
      
      // Send email with reset link (in production)
      // For development/testing, we'll just log it
      const resetLink = `http://localhost:${PORT}/reset-password?token=${token}`;
      console.log(`Password reset link for ${email}: ${resetLink}`);
      
      // In production, you would use nodemailer:
      /*
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'your-email@gmail.com',
          pass: 'your-app-password'
        }
      });
      
      const mailOptions = {
        from: 'your-email@gmail.com',
        to: email,
        subject: 'Password Reset Request',
        html: `
          <h1>Password Reset</h1>
          <p>You requested a password reset. Click the link below to reset your password:</p>
          <a href="${resetLink}">Reset Password</a>
          <p>This link will expire in 1 hour.</p>
          <p>If you didn't request this, please ignore this email.</p>
        `
      };
      
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
        } else {
          console.log('Email sent:', info.response);
        }
      });
      */
      
      res.redirect('/forgot-password?sent=true');
    });
  });
});

app.get('/reset-password', (req, res) => {
  const { token } = req.query;
  
  if (!token) {
    return res.redirect('/login');
  }
  
  // Check if token exists and is valid
  const query = `
    SELECT pr.*, u.email 
    FROM PasswordResets pr
    JOIN Users u ON pr.user_id = u.user_id
    WHERE pr.token = ? AND pr.expires_at > NOW() AND pr.used = 0
  `;
  
  db.query(query, [token], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.redirect('/login?error=server');
    }
    
    if (results.length === 0) {
      return res.redirect('/login?error=invalid-token');
    }
    
    // Token is valid, show reset password form
    res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
  });
});

app.post('/reset-password', (req, res) => {
  const { token, password, confirmPassword } = req.body;
  
  // Validate passwords match
  if (password !== confirmPassword) {
    return res.redirect(`/reset-password?token=${token}&error=password`);
  }
  
  // Check if token exists and is valid
  const query = `
    SELECT * FROM PasswordResets
    WHERE token = ? AND expires_at > NOW() AND used = 0
  `;
  
  db.query(query, [token], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.redirect(`/reset-password?token=${token}&error=server`);
    }
    
    if (results.length === 0) {
      return res.redirect('/login?error=invalid-token');
    }
    
    const resetRecord = results[0];
    
    // Hash the new password
    // const hashedPassword = bcrypt.hashSync(password, 10);
    const hashedPassword = password; // For development without bcrypt
    
    // Update user password
    db.query('UPDATE Users SET password = ? WHERE user_id = ?', 
      [hashedPassword, resetRecord.user_id], (err) => {
      if (err) {
        console.error('Error updating password:', err);
        return res.redirect(`/reset-password?token=${token}&error=server`);
      }
      
      // Mark reset token as used
      db.query('UPDATE PasswordResets SET used = 1 WHERE reset_id = ?', 
        [resetRecord.reset_id], (err) => {
        if (err) {
          console.error('Error marking token as used:', err);
        }
      });
      
      // Redirect to login with success message
      res.redirect('/login?reset=success');
    });
  });
});

// Dashboard route (protected)
app.get('/dashboard', authenticateUser, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// API route to get user's transactions (protected)
app.get('/api/transactions', authenticateUser, (req, res) => {
  // Get transactions for the logged-in user
  const userId = req.session.userId;
  const query = `
    SELECT t.*, c.first_name, c.last_name, a.account_type, b.bank_name 
    FROM Transactions t
    JOIN Accounts a ON t.customer_account = a.account_id
    JOIN Customers c ON a.customer_id = c.customer_id
    LEFT JOIN Banks b ON t.bank_id = b.bank_id
    WHERE a.customer_id IN (
      SELECT customer_id FROM Accounts WHERE account_id = t.customer_account
    )
    ORDER BY transaction_date DESC
    LIMIT 100
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching transactions:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    res.json(results);
  });
});

// API route to get fraud alerts (protected)
app.get('/api/alerts', authenticateUser, (req, res) => {
  const userId = req.session.userId;
  const userRole = req.session.role;
  
  // Different queries based on user role
  let query;
  let queryParams;
  
  if (userRole === 'admin') {
    // Admins can see all alerts
    query = `
      SELECT fa.*, c.first_name, c.last_name, c.email, t.amount, t.transaction_date, t.transaction_type
      FROM FraudAlerts fa
      JOIN Transactions t ON fa.transaction_id = t.transaction_id
      JOIN Accounts a ON t.customer_account = a.account_id
      JOIN Customers c ON a.customer_id = c.customer_id
      ORDER BY fa.alert_date DESC
      LIMIT 100
    `;
    queryParams = [];
  } else if (userRole === 'analyst') {
    // Analysts can see alerts assigned to them or unassigned
    query = `
      SELECT fa.*, c.first_name, c.last_name, c.email, t.amount, t.transaction_date, t.transaction_type
      FROM FraudAlerts fa
      JOIN Transactions t ON fa.transaction_id = t.transaction_id
      JOIN Accounts a ON t.customer_account = a.account_id
      JOIN Customers c ON a.customer_id = c.customer_id
      JOIN AlertsHistory ah ON fa.alert_id = ah.alert_id
      WHERE ah.resolved_by IS NULL OR ah.resolved_by = ?
      ORDER BY fa.alert_date DESC
      LIMIT 100
    `;
    queryParams = [userId];
  } else {
    // Regular users can only see their own alerts
    query = `
      SELECT fa.*, t.amount, t.transaction_date, t.transaction_type
      FROM FraudAlerts fa
      JOIN Transactions t ON fa.transaction_id = t.transaction_id
      JOIN Accounts a ON t.customer_account = a.account_id
      JOIN Customers c ON a.customer_id = c.customer_id
      WHERE c.customer_id = ?
      ORDER BY fa.alert_date DESC
      LIMIT 100
    `;
    queryParams = [userId];
  }
  
  db.query(query, queryParams, (err, results) => {
    if (err) {
      console.error('Error fetching alerts:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    res.json(results);
  });
});

// API route to update alert status (protected - admin/analyst only)
app.post('/api/alerts/:alertId', authenticateUser, (req, res) => {
  const { alertId } = req.params;
  const { status, resolution, notes } = req.body;
  const userId = req.session.userId;
  const userRole = req.session.role;
  
  // Only admins and analysts can update alerts
  if (userRole !== 'admin' && userRole !== 'analyst') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  // Begin transaction
  db.beginTransaction(err => {
    if (err) {
      console.error('Error starting transaction:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    // Update alert status
    const updateAlertQuery = `
      UPDATE FraudAlerts
      SET alert_status = ?
      WHERE alert_id = ?
    `;
    
    db.query(updateAlertQuery, [status, alertId], (err, results) => {
      if (err) {
        return db.rollback(() => {
          console.error('Error updating alert:', err);
          res.status(500).json({ error: 'Internal server error' });
        });
      }
      
      // Add entry to AlertsHistory
      const updateHistoryQuery = `
        INSERT INTO AlertsHistory (alert_id, alert_resolution, resolved_by, resolution_date)
        VALUES (?, ?, ?, NOW())
        ON DUPLICATE KEY UPDATE 
        alert_resolution = VALUES(alert_resolution),
        resolved_by = VALUES(resolved_by),
        resolution_date = VALUES(resolution_date)
      `;
      
      db.query(updateHistoryQuery, [
        alertId, 
        resolution || status, 
        userId
      ], (err, results) => {
        if (err) {
          return db.rollback(() => {
            console.error('Error updating alert history:', err);
            res.status(500).json({ error: 'Internal server error' });
          });
        }
        
        // Commit transaction
        db.commit(err => {
          if (err) {
            return db.rollback(() => {
              console.error('Error committing transaction:', err);
              res.status(500).json({ error: 'Internal server error' });
            });
          }
          
          res.json({ success: true });
        });
      });
    });
  });
});

// New API endpoints for other tables

// API endpoint for customers (protected - admin only)
app.get('/api/customers', authenticateUser, (req, res) => {
  const userRole = req.session.role;
  
  if (userRole !== 'admin' && userRole !== 'analyst') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  const query = `
    SELECT c.*, 
           COUNT(DISTINCT a.account_id) as account_count,
           SUM(CASE WHEN a.account_status = 'Active' THEN 1 ELSE 0 END) as active_accounts
    FROM Customers c
    LEFT JOIN Accounts a ON c.customer_id = a.customer_id
    GROUP BY c.customer_id
    ORDER BY c.customer_since DESC
    LIMIT 1000
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching customers:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    res.json(results);
  });
});

// API endpoint for accounts (protected)
app.get('/api/accounts', authenticateUser, (req, res) => {
  const userId = req.session.userId;
  const userRole = req.session.role;
  
  let query;
  let queryParams;
  
  if (userRole === 'admin' || userRole === 'analyst') {
    // Admins and analysts can see all accounts
    query = `
      SELECT a.*, c.first_name, c.last_name, c.email,
             r.risk_score
      FROM Accounts a
      JOIN Customers c ON a.customer_id = c.customer_id
      LEFT JOIN RiskLevel r ON a.account_id = r.account_id
      ORDER BY a.creation_date DESC
      LIMIT 1000
    `;
    queryParams = [];
  } else {
    // Regular users can only see their own accounts
    query = `
      SELECT a.*, c.first_name, c.last_name, c.email,
             r.risk_score
      FROM Accounts a
      JOIN Customers c ON a.customer_id = c.customer_id
      LEFT JOIN RiskLevel r ON a.account_id = r.account_id
      WHERE c.customer_id = ?
      ORDER BY a.creation_date DESC
    `;
    queryParams = [userId];
  }
  
  db.query(query, queryParams, (err, results) => {
    if (err) {
      console.error('Error fetching accounts:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    res.json(results);
  });
});

// API endpoint for high risk accounts
app.get('/api/high-risk-accounts', authenticateUser, (req, res) => {
  const userRole = req.session.role;
  
  if (userRole !== 'admin' && userRole !== 'analyst') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  const query = `
    SELECT a.*, c.first_name, c.last_name, c.email, r.risk_score
    FROM Accounts a
    JOIN Customers c ON a.customer_id = c.customer_id
    JOIN RiskLevel r ON a.account_id = r.account_id
    WHERE r.risk_score > 70
    ORDER BY r.risk_score DESC
    LIMIT 100
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching high risk accounts:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    res.json(results);
  });
});

// API endpoint for login attempts
app.get('/api/login-attempts', authenticateUser, (req, res) => {
  const userRole = req.session.role;
  
  if (userRole !== 'admin' && userRole !== 'analyst') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  const query = `
    SELECT l.*, c.first_name, c.last_name, c.email,
           d.device_type, d.device_os, d.ip_address,
           g.latitude, g.longitude
    FROM LoginAttempts l
    JOIN Customers c ON l.customer_id = c.customer_id
    JOIN Devices d ON l.device_id = d.device_id
    JOIN Geolocation g ON l.geolocation_id = g.geolocation_id
    WHERE l.login_status = 'Failed'
    ORDER BY l.login_date DESC
    LIMIT 100
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching login attempts:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    res.json(results);
  });
});

// API endpoint for device information
app.get('/api/devices', authenticateUser, (req, res) => {
  const userRole = req.session.role;
  
  if (userRole !== 'admin' && userRole !== 'analyst') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  const query = `
    SELECT d.*, c.first_name, c.last_name, c.email,
           g.latitude, g.longitude
    FROM Devices d
    JOIN Customers c ON d.customer_id = c.customer_id
    LEFT JOIN Geolocation g ON d.geolocation_id = g.geolocation_id
    ORDER BY d.last_used DESC
    LIMIT 100
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching devices:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    res.json(results);
  });
});

// API endpoint for dashboard summary
app.get('/api/dashboard-summary', authenticateUser, (req, res) => {
  // Get summary counts for dashboard statistics
  const queryCounts = `
    SELECT
      (SELECT COUNT(*) FROM FraudAlerts WHERE alert_status = 'Open') AS openAlerts,
      (SELECT COUNT(*) FROM RiskLevel WHERE risk_score > 70) AS highRiskAccounts,
      (SELECT COUNT(*) FROM LoginAttempts WHERE login_status = 'Failed' AND login_date > DATE_SUB(NOW(), INTERVAL 24 HOUR)) AS failedLogins,
      (SELECT COUNT(*) FROM Transactions WHERE transaction_status = 'Suspended') AS suspendedTransactions
  `;
  
  db.query(queryCounts, (err, results) => {
    if (err) {
      console.error('Error fetching dashboard summary:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    // Get alert types distribution
    const queryAlertTypes = `
      SELECT alert_type, COUNT(*) as count
      FROM FraudAlerts
      GROUP BY alert_type
      ORDER BY count DESC
      LIMIT 5
    `;
    
    db.query(queryAlertTypes, (err, alertTypes) => {
      if (err) {
        console.error('Error fetching alert types:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      
      // Get risk score distribution
      const queryRiskDistribution = `
        SELECT 
          CASE
            WHEN risk_score BETWEEN 0 AND 25 THEN 'Low (0-25)'
            WHEN risk_score BETWEEN 26 AND 50 THEN 'Medium (26-50)'
            WHEN risk_score BETWEEN 51 AND 75 THEN 'High (51-75)'
            ELSE 'Critical (76-100)'
          END AS risk_category,
          COUNT(*) as count
        FROM RiskLevel
        GROUP BY risk_category
        ORDER BY 
          CASE risk_category
            WHEN 'Low (0-25)' THEN 1
            WHEN 'Medium (26-50)' THEN 2
            WHEN 'High (51-75)' THEN 3
            WHEN 'Critical (76-100)' THEN 4
          END
      `;
      
      db.query(queryRiskDistribution, (err, riskDistribution) => {
        if (err) {
          console.error('Error fetching risk distribution:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        // Get recent high priority alerts
        const queryRecentAlerts = `
          SELECT fa.*, c.first_name, c.last_name, t.amount, t.transaction_date
          FROM FraudAlerts fa
          JOIN Transactions t ON fa.transaction_id = t.transaction_id
          JOIN Accounts a ON t.customer_account = a.account_id
          JOIN Customers c ON a.customer_id = c.customer_id
          WHERE fa.alert_priority = 'High'
          ORDER BY fa.alert_date DESC
          LIMIT 10
        `;
        
        db.query(queryRecentAlerts, (err, recentAlerts) => {
          if (err) {
            console.error('Error fetching recent alerts:', err);
            return res.status(500).json({ error: 'Internal server error' });
          }
          
          // Combine all results
          res.json({
            counts: results[0],
            alertTypes: alertTypes,
            riskDistribution: riskDistribution,
            recentAlerts: recentAlerts
          });
        });
      });
    });
  });
});

// User profile routes
app.get('/profile', authenticateUser, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/api/profile', authenticateUser, (req, res) => {
  const userId = req.session.userId;
  
  const query = `
    SELECT user_id, username, first_name, last_name, email, role, created_at, last_login
    FROM Users
    WHERE user_id = ?
  `;
  
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching profile:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(results[0]);
  });
});

app.post('/api/profile', authenticateUser, (req, res) => {
  const userId = req.session.userId;
  const { firstName, lastName, email } = req.body;
  
  const query = `
    UPDATE Users
    SET first_name = ?, last_name = ?, email = ?
    WHERE user_id = ?
  `;
  
  db.query(query, [firstName, lastName, email, userId], (err) => {
    if (err) {
      console.error('Error updating profile:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    res.json({ success: true });
  });
});

// Change password route
app.post('/api/change-password', authenticateUser, (req, res) => {
      const userId = req.session.userId;
      const { currentPassword, newPassword, confirmPassword } = req.body;
      
      // Validate password confirmation
      if (newPassword !== confirmPassword) {
        return res.status(400).json({ error: 'Passwords do not match' });
      }
      
      // Get current user
      db.query('SELECT password FROM Users WHERE user_id = ?', [userId], (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (results.length === 0) {
          return res.status(404).json({ error: 'User not found' });
        }
        
        const user = results[0];
        
        // For development/testing (REPLACE WITH BCRYPT IN PRODUCTION)
        if (currentPassword === user.password) {
          // For now, without bcrypt:
          const hashedPassword = newPassword;
          
          // Update password
          db.query('UPDATE Users SET password = ? WHERE user_id = ?', 
            [hashedPassword, userId], (err) => {
            if (err) {
              console.error('Error updating password:', err);
              return res.status(500).json({ error: 'Internal server error' });
            }
            
            res.json({ success: true });
          });
        } else {
          res.status(400).json({ error: 'Current password is incorrect' });
        }
        
        // For production (uncomment when using bcrypt)
        /*
        bcrypt.compare(currentPassword, user.password, (err, isMatch) => {
          if (err || !isMatch) {
            return res.status(400).json({ error: 'Current password is incorrect' });
          }
          
          // Hash the new password
          bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
            if (err) {
              console.error('Error hashing password:', err);
              return res.status(500).json({ error: 'Internal server error' });
            }
            
            // Update password
            db.query('UPDATE Users SET password = ? WHERE user_id = ?', 
              [hashedPassword, userId], (err) => {
              if (err) {
                console.error('Error updating password:', err);
                return res.status(500).json({ error: 'Internal server error' });
              }
              
              res.json({ success: true });
            });
          });
        });
        */
      });
    });
    
    // Logout route
    app.get('/logout', (req, res) => {
      req.session.destroy((err) => {
        if (err) {
          console.error('Error destroying session:', err);
        }
        res.redirect('/login');
      });
    });
    
    // API endpoint for risk level data
    app.get('/api/risk-levels', authenticateUser, (req, res) => {
      const userRole = req.session.role;
      
      if (userRole !== 'admin' && userRole !== 'analyst') {
        return res.status(403).json({ error: 'Unauthorized' });
      }
      
      const query = `
        SELECT r.*, a.account_type, c.first_name, c.last_name, c.email,
               d.device_type, d.device_os, d.ip_address
        FROM RiskLevel r
        JOIN Accounts a ON r.account_id = a.account_id
        JOIN Customers c ON a.customer_id = c.customer_id
        LEFT JOIN Devices d ON r.device_at_risk = d.device_id
        ORDER BY r.risk_score DESC
        LIMIT 100
      `;
      
      db.query(query, (err, results) => {
        if (err) {
          console.error('Error fetching risk levels:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        res.json(results);
      });
    });
    
    // API endpoint for alert history
    app.get('/api/alert-history/:alertId', authenticateUser, (req, res) => {
      const { alertId } = req.params;
      const userRole = req.session.role;
      
      if (userRole !== 'admin' && userRole !== 'analyst') {
        return res.status(403).json({ error: 'Unauthorized' });
      }
      
      const query = `
        SELECT ah.*, u.first_name, u.last_name
        FROM AlertsHistory ah
        LEFT JOIN Users u ON ah.resolved_by = u.user_id
        WHERE ah.alert_id = ?
        ORDER BY ah.resolution_date DESC
      `;
      
      db.query(query, [alertId], (err, results) => {
        if (err) {
          console.error('Error fetching alert history:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        res.json(results);
      });
    });
    
    // API endpoint for customer details
    app.get('/api/customers/:customerId', authenticateUser, (req, res) => {
      const { customerId } = req.params;
      const userRole = req.session.role;
      
      if (userRole !== 'admin' && userRole !== 'analyst') {
        return res.status(403).json({ error: 'Unauthorized' });
      }
      
      const query = `
        SELECT * FROM Customers
        WHERE customer_id = ?
      `;
      
      db.query(query, [customerId], (err, results) => {
        if (err) {
          console.error('Error fetching customer:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (results.length === 0) {
          return res.status(404).json({ error: 'Customer not found' });
        }
        
        // Get customer accounts
        const accountsQuery = `
          SELECT a.*, r.risk_score
          FROM Accounts a
          LEFT JOIN RiskLevel r ON a.account_id = r.account_id
          WHERE a.customer_id = ?
        `;
        
        db.query(accountsQuery, [customerId], (err, accounts) => {
          if (err) {
            console.error('Error fetching customer accounts:', err);
            return res.status(500).json({ error: 'Internal server error' });
          }
          
          // Get customer devices
          const devicesQuery = `
            SELECT d.*, g.latitude, g.longitude
            FROM Devices d
            LEFT JOIN Geolocation g ON d.geolocation_id = g.geolocation_id
            WHERE d.customer_id = ?
          `;
          
          db.query(devicesQuery, [customerId], (err, devices) => {
            if (err) {
              console.error('Error fetching customer devices:', err);
              return res.status(500).json({ error: 'Internal server error' });
            }
            
            // Get customer transactions
            const transactionsQuery = `
              SELECT t.*, fa.alert_id, fa.alert_type, fa.alert_status, fa.alert_priority
              FROM Transactions t
              JOIN Accounts a ON t.customer_account = a.account_id
              LEFT JOIN FraudAlerts fa ON t.transaction_id = fa.transaction_id
              WHERE a.customer_id = ?
              ORDER BY t.transaction_date DESC
              LIMIT 100
            `;
            
            db.query(transactionsQuery, [customerId], (err, transactions) => {
              if (err) {
                console.error('Error fetching customer transactions:', err);
                return res.status(500).json({ error: 'Internal server error' });
              }
              
              // Combine all customer data
              res.json({
                customer: results[0],
                accounts: accounts,
                devices: devices,
                transactions: transactions
              });
            });
          });
        });
      });
    });
    
    // API endpoint for transaction details
    app.get('/api/transactions/:transactionId', authenticateUser, (req, res) => {
      const { transactionId } = req.params;
      
      const query = `
        SELECT t.*, c.first_name, c.last_name, c.email,
               a.account_type as sender_account_type,
               ra.account_type as receiver_account_type,
               b.bank_name, g.latitude, g.longitude,
               d.device_type, d.device_os, d.ip_address as device_ip
        FROM Transactions t
        JOIN Accounts a ON t.customer_account = a.account_id
        JOIN Customers c ON a.customer_id = c.customer_id
        LEFT JOIN Accounts ra ON t.reciever_account = ra.account_id
        LEFT JOIN Banks b ON t.bank_id = b.bank_id
        LEFT JOIN Geolocation g ON t.geolocation_id = g.geolocation_id
        LEFT JOIN Devices d ON t.device_id = d.device_id
        WHERE t.transaction_id = ?
      `;
      
      db.query(query, [transactionId], (err, results) => {
        if (err) {
          console.error('Error fetching transaction:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (results.length === 0) {
          return res.status(404).json({ error: 'Transaction not found' });
        }
        
        // Check for fraud alerts associated with this transaction
        const alertQuery = `
          SELECT fa.*, ah.alert_resolution, ah.resolution_date, 
                 u.first_name as resolver_first_name, u.last_name as resolver_last_name
          FROM FraudAlerts fa
          LEFT JOIN AlertsHistory ah ON fa.alert_id = ah.alert_id
          LEFT JOIN Users u ON ah.resolved_by = u.user_id
          WHERE fa.transaction_id = ?
        `;
        
        db.query(alertQuery, [transactionId], (err, alerts) => {
          if (err) {
            console.error('Error fetching alerts:', err);
            return res.status(500).json({ error: 'Internal server error' });
          }
          
          res.json({
            transaction: results[0],
            alerts: alerts
          });
        });
      });
    });
    
    // API endpoint for geolocation data
    app.get('/api/geolocations', authenticateUser, (req, res) => {
      const userRole = req.session.role;
      
      if (userRole !== 'admin' && userRole !== 'analyst') {
        return res.status(403).json({ error: 'Unauthorized' });
      }
      
      const query = `
        SELECT g.*, 
               COUNT(DISTINCT t.transaction_id) as transaction_count,
               COUNT(DISTINCT l.login_id) as login_count
        FROM Geolocation g
        LEFT JOIN Transactions t ON g.geolocation_id = t.geolocation_id
        LEFT JOIN LoginAttempts l ON g.geolocation_id = l.geolocation_id
        GROUP BY g.geolocation_id
        ORDER BY g.location_detected DESC
        LIMIT 100
      `;
      
      db.query(query, (err, results) => {
        if (err) {
          console.error('Error fetching geolocations:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        res.json(results);
      });
    });
    
    // API endpoint for bank details
    app.get('/api/banks', authenticateUser, (req, res) => {
      const userRole = req.session.role;
      
      if (userRole !== 'admin' && userRole !== 'analyst') {
        return res.status(403).json({ error: 'Unauthorized' });
      }
      
      const query = `
        SELECT b.*, 
               COUNT(DISTINCT t.transaction_id) as transaction_count
        FROM Banks b
        LEFT JOIN Transactions t ON b.bank_id = t.bank_id
        GROUP BY b.bank_id
        ORDER BY transaction_count DESC
      `;
      
      db.query(query, (err, results) => {
        if (err) {
          console.error('Error fetching banks:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        res.json(results);
      });
    });
    
    // API endpoint for creating a new fraud alert (admin/analyst)
    app.post('/api/alerts', authenticateUser, (req, res) => {
      const userRole = req.session.role;
      
      if (userRole !== 'admin' && userRole !== 'analyst') {
        return res.status(403).json({ error: 'Unauthorized' });
      }
      
      const { transactionId, alertType, alertMessage, alertPriority } = req.body;
      
      // Validate transaction exists
      db.query('SELECT * FROM Transactions WHERE transaction_id = ?', [transactionId], (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        if (results.length === 0) {
          return res.status(404).json({ error: 'Transaction not found' });
        }
        
        // Create alert
        const query = `
          INSERT INTO FraudAlerts 
          (transaction_id, alert_type, alert_date, alert_status, alert_message, alert_priority)
          VALUES (?, ?, NOW(), 'Open', ?, ?)
        `;
        
        db.query(query, [
          transactionId,
          alertType,
          alertMessage,
          alertPriority || 'Medium'
        ], (err, results) => {
          if (err) {
            console.error('Error creating alert:', err);
            return res.status(500).json({ error: 'Internal server error' });
          }
          
          res.json({ 
            success: true, 
            alertId: results.insertId 
          });
        });
      });
    });
    
    // API endpoint for updating customer risk score
    app.put('/api/risk-levels/:accountId', authenticateUser, (req, res) => {
      const { accountId } = req.params;
      const { riskScore, deviceAtRisk } = req.body;
      const userRole = req.session.role;
      
      if (userRole !== 'admin' && userRole !== 'analyst') {
        return res.status(403).json({ error: 'Unauthorized' });
      }
      
      // Check if risk level exists for this account
      db.query('SELECT * FROM RiskLevel WHERE account_id = ?', [accountId], (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        let query;
        let params;
        
        if (results.length === 0) {
          // Insert new risk level
          query = `
            INSERT INTO RiskLevel 
            (account_id, device_at_risk, risk_score, last_assessment_date)
            VALUES (?, ?, ?, NOW())
          `;
          params = [accountId, deviceAtRisk || null, riskScore];
        } else {
          // Update existing risk level
          query = `
            UPDATE RiskLevel
            SET risk_score = ?, 
                device_at_risk = ?, 
                last_assessment_date = NOW()
            WHERE account_id = ?
          `;
          params = [riskScore, deviceAtRisk || null, accountId];
        }
        
        db.query(query, params, (err) => {
          if (err) {
            console.error('Error updating risk level:', err);
            return res.status(500).json({ error: 'Internal server error' });
          }
          
          res.json({ success: true });
        });
      });
    });
    
    // API endpoint for adding a new device
    app.post('/api/devices', authenticateUser, (req, res) => {
      const { customerId, ipAddress, deviceType, deviceOs, latitude, longitude } = req.body;
      
      // Begin transaction
      db.beginTransaction(err => {
        if (err) {
          console.error('Error starting transaction:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        // First create geolocation record if latitude/longitude provided
        if (latitude && longitude) {
          const geoQuery = `
            INSERT INTO Geolocation 
            (latitude, longitude, location_detected)
            VALUES (?, ?, NOW())
          `;
          
          db.query(geoQuery, [latitude, longitude], (err, geoResults) => {
            if (err) {
              return db.rollback(() => {
                console.error('Error creating geolocation:', err);
                res.status(500).json({ error: 'Internal server error' });
              });
            }
            
            const geolocationId = geoResults.insertId;
            
            // Now create device record
            createDevice(customerId, ipAddress, deviceType, deviceOs, geolocationId);
          });
        } else {
          // Create device without geolocation
          createDevice(customerId, ipAddress, deviceType, deviceOs, null);
        }
        
        function createDevice(customerId, ipAddress, deviceType, deviceOs, geolocationId) {
          const deviceQuery = `
            INSERT INTO Devices 
            (customer_id, ip_address, device_type, device_os, first_used, last_used, geolocation_id)
            VALUES (?, ?, ?, ?, NOW(), NOW(), ?)
          `;
          
          db.query(deviceQuery, [
            customerId,
            ipAddress,
            deviceType,
            deviceOs,
            geolocationId
          ], (err, deviceResults) => {
            if (err) {
              return db.rollback(() => {
                console.error('Error creating device:', err);
                res.status(500).json({ error: 'Internal server error' });
              });
            }
            
            // Commit transaction
            db.commit(err => {
              if (err) {
                return db.rollback(() => {
                  console.error('Error committing transaction:', err);
                  res.status(500).json({ error: 'Internal server error' });
                });
              }
              
              res.json({ 
                success: true, 
                deviceId: deviceResults.insertId 
              });
            });
          });
        }
      });
    });
    
    // API endpoint for recording login attempts
    app.post('/api/login-attempts', authenticateUser, (req, res) => {
      const { customerId, deviceId, loginStatus, latitude, longitude } = req.body;
      
      // Begin transaction
      db.beginTransaction(err => {
        if (err) {
          console.error('Error starting transaction:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        // First create geolocation record if latitude/longitude provided
        if (latitude && longitude) {
          const geoQuery = `
            INSERT INTO Geolocation 
            (latitude, longitude, location_detected)
            VALUES (?, ?, NOW())
          `;
          
          db.query(geoQuery, [latitude, longitude], (err, geoResults) => {
            if (err) {
              return db.rollback(() => {
                console.error('Error creating geolocation:', err);
                res.status(500).json({ error: 'Internal server error' });
              });
            }
            
            const geolocationId = geoResults.insertId;
            
            // Now create login attempt record
            createLoginAttempt(customerId, deviceId, loginStatus, geolocationId);
          });
        } else {
          // Create login attempt without geolocation
          createLoginAttempt(customerId, deviceId, loginStatus, null);
        }
        
        function createLoginAttempt(customerId, deviceId, loginStatus, geolocationId) {
          const loginQuery = `
            INSERT INTO LoginAttempts 
            (customer_id, login_date, device_id, login_status, geolocation_id)
            VALUES (?, NOW(), ?, ?, ?)
          `;
          
          db.query(loginQuery, [
            customerId,
            deviceId,
            loginStatus,
            geolocationId
          ], (err, loginResults) => {
            if (err) {
              return db.rollback(() => {
                console.error('Error creating login attempt:', err);
                res.status(500).json({ error: 'Internal server error' });
              });
            }
            
            // Commit transaction
            db.commit(err => {
              if (err) {
                return db.rollback(() => {
                  console.error('Error committing transaction:', err);
                  res.status(500).json({ error: 'Internal server error' });
                });
              }
              
              res.json({ 
                success: true, 
                loginId: loginResults.insertId 
              });
            });
          });
        }
      });
    });
    
    // API endpoint for creating or updating a transaction
    app.post('/api/transactions', authenticateUser, (req, res) => {
      const {
        transactionType,
        customerAccount,
        receiverAccount,
        amount,
        ipAddress,
        deviceId,
        bankId,
        latitude,
        longitude,
        transactionStatus
      } = req.body;
      
      // Begin transaction
      db.beginTransaction(err => {
        if (err) {
          console.error('Error starting transaction:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        // First create geolocation record if latitude/longitude provided
        if (latitude && longitude) {
          const geoQuery = `
            INSERT INTO Geolocation 
            (latitude, longitude, location_detected)
            VALUES (?, ?, NOW())
          `;
          
          db.query(geoQuery, [latitude, longitude], (err, geoResults) => {
            if (err) {
              return db.rollback(() => {
                console.error('Error creating geolocation:', err);
                res.status(500).json({ error: 'Internal server error' });
              });
            }
            
            const geolocationId = geoResults.insertId;
            
            // Now create transaction record
            createTransaction(
              transactionType,
              customerAccount,
              receiverAccount,
              amount,
              ipAddress,
              deviceId,
              bankId,
              geolocationId,
              transactionStatus
            );
          });
        } else {
          // Create transaction without geolocation
          createTransaction(
            transactionType,
            customerAccount,
            receiverAccount,
            amount,
            ipAddress,
            deviceId,
            bankId,
            null,
            transactionStatus
          );
        }
        
        function createTransaction(
          transactionType,
          customerAccount,
          receiverAccount,
          amount,
          ipAddress,
          deviceId,
          bankId,
          geolocationId,
          transactionStatus
        ) {
          const transactionQuery = `
            INSERT INTO Transactions 
            (transaction_type, customer_account, reciever_account, amount, 
             transaction_date, transaction_status, ip_address, 
             geolocation_id, bank_id, device_id)
            VALUES (?, ?, ?, ?, NOW(), ?, ?, ?, ?, ?)
          `;
          
          db.query(transactionQuery, [
            transactionType,
            customerAccount,
            receiverAccount || null,
            amount,
            transactionStatus || 'Pending',
            ipAddress,
            geolocationId,
            bankId || null,
            deviceId || null
          ], (err, transactionResults) => {
            if (err) {
              return db.rollback(() => {
                console.error('Error creating transaction:', err);
                res.status(500).json({ error: 'Internal server error' });
              });
            }
            
            // Commit transaction
            db.commit(err => {
              if (err) {
                return db.rollback(() => {
                  console.error('Error committing transaction:', err);
                  res.status(500).json({ error: 'Internal server error' });
                });
              }
              
              res.json({ 
                success: true, 
                transactionId: transactionResults.insertId 
              });
            });
          });
        }
      });
    });
    
    // Start the server
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
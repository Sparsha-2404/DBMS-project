CREATE DATABASE Frauddetection;
USE Frauddetection;

CREATE TABLE Customers (
    customer_id BIGINT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    phone_number VARCHAR(15) NOT NULL,
    address VARCHAR(255) NOT NULL,
    profession VARCHAR(50) NOT NULL,
    date_of_birth DATE NOT NULL,
    customer_since DATE
);

CREATE TABLE Accounts (
    account_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    customer_id BIGINT,
    account_type ENUM('savings', 'salary', 'checking', 'credit') NOT NULL,-- savings, salary, etc
    balance DECIMAL(15, 2),
    account_status ENUM('Active', 'Suspended', 'Closed') NOT NULL,  -- Active, Suspended, Closed
    creation_date DATE,
    last_updated DATE,
    FOREIGN KEY (customer_id) REFERENCES Customers(customer_id)
);

CREATE TABLE Geolocation (
    geolocation_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    latitude DECIMAL(9, 6),  -- Latitude of transaction or login
    longitude DECIMAL(9, 6),  -- Longitude of transaction or login
    location_detected TIMESTAMP NOT NULL
);

CREATE TABLE Banks (
	bank_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    bank_name VARCHAR(50),
    bank_code VARCHAR(50) UNIQUE NULL,  -- Because the reciever can be of the same bank as the sender
    bank_address VARCHAR(200) NULL
);

CREATE TABLE Devices (
    device_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    customer_id BIGINT,
    ip_address VARCHAR(45),
    device_type ENUM('Mobile', 'Desktop', 'Tablet') NOT NULL,  -- Mobile, Desktop, etc.
    device_os VARCHAR(50),  -- iOS, Android, Windows, etc.
    first_used TIMESTAMP,
    last_used TIMESTAMP,
    geolocation_id BIGINT,
    FOREIGN KEY (customer_id) REFERENCES Customers(customer_id),
    FOREIGN KEY (geolocation_id) REFERENCES Geolocation(geolocation_id)
);

CREATE TABLE Transactions (
    transaction_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    transaction_type ENUM('Deposit', 'Withdrawal', 'Transfer', 'Payment') NOT NULL,  -- Deposit, Withdrawal, Transfer
    customer_account BIGINT NOT NULL, -- Account ID: from where money was transfered
    reciever_account BIGINT NULL,  -- Account ID: where money was transfered to (opptional)
    amount DECIMAL(15, 2) NOT NULL,
    transaction_date TIMESTAMP NOT NULL,
    transaction_status ENUM('Pending', 'Completed', 'Failed', 'Suspended') NOT NULL, -- Pending, Completed, Failed, Suspended
    ip_address VARCHAR(45) NULL,
    geolocation_id BIGINT NULL,  -- Geo-location of transaction
    bank_id BIGINT NULL,         -- In case the reciever account is not in the same bank as the sender
    device_id BIGINT NULL,
    FOREIGN KEY (customer_account) REFERENCES Accounts(account_id),
    FOREIGN KEY (reciever_account) REFERENCES Accounts(account_id),
    FOREIGN KEY (geolocation_id) REFERENCES Geolocation(geolocation_id),
    FOREIGN KEY (bank_id) REFERENCES Banks(bank_id),
    FOREIGN KEY (device_id) REFERENCES Devices(device_id),
    INDEX (customer_account),
    INDEX (transaction_date),
    INDEX (transaction_status)
);

CREATE TABLE FraudAlerts (    -- Based on transaction to transaction
    alert_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    transaction_id BIGINT,
    alert_type VARCHAR(50),  -- E.g., "Suspicious Withdrawal", "Unusual Login"
    alert_date TIMESTAMP,
    alert_status ENUM('Open', 'Closed', 'Investigating') NOT NULL,  -- Open, Closed, Investigating
    alert_message TEXT,  -- Details of why the alert was triggered
    alert_priority ENUM('Low', 'Medium', 'High') NOT NULL,  -- Low, Medium, High (EX-->  Low: wrong password entered one time, High: wrong password multiple times)
    customer_notified BOOLEAN DEFAULT FALSE,  -- Whether the customer was notified
    FOREIGN KEY (transaction_id) REFERENCES Transactions(transaction_id)
);

CREATE TABLE RiskLevel (     -- Based on customer to identify vulnerable groups like senior citizens or specially abled
    account_id BIGINT,
    device_at_risk BIGINT,      -- In case suspicious activity has taken place on same device previously
    risk_score DECIMAL(5, 2),  -- A calculated score based on behavior (e.g., 0-100)
    last_assessment_date TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES Accounts(account_id),
    FOREIGN KEY (device_at_risk) REFERENCES Devices(device_id)
);

CREATE TABLE LoginAttempts (
    login_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    customer_id BIGINT,
    login_date TIMESTAMP,
    device_id BIGINT,
    login_status ENUM('Successful', 'Failed') NOT NULL,  -- Successful, Failed
    geolocation_id BIGINT,
    FOREIGN KEY (customer_id) REFERENCES Customers(customer_id),
    FOREIGN KEY (device_id) REFERENCES Devices(device_id),
    FOREIGN KEY (geolocation_id) REFERENCES Geolocation(geolocation_id)
);

CREATE TABLE AlertsHistory (
    alert_id BIGINT,
    alert_resolution VARCHAR(100),  -- E.g., "Resolved", "Escalated"
    resolved_by VARCHAR(100),  -- Analyst who resolved it
    resolution_date TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES FraudAlerts(alert_id)
);

-- Add this to your database schema

CREATE TABLE Users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'analyst',
    last_login DATETIME,
    created_at DATETIME NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT chk_role CHECK (role IN ('analyst', 'supervisor', 'admin'))
);
Select * from users;
Select * from customers;
Select * from accounts;
Select * from geolocation;
Select * from banks;
Select * from devices;
Select * from transactions;
Select * from fraudalerts;
Select * from risklevel;
Select * from loginattempts;
Select * from alertshistory;

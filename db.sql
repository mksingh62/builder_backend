-- Database Schema for House Construction Management System
-- Run this in XAMPP phpMyAdmin or via MySQL command line

-- Create Database
CREATE DATABASE IF NOT EXISTS house_construction_db;
USE house_construction_db;

-- ====================================================
-- 1. Users Table
-- ====================================================
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    phone VARCHAR(15) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'staff', 'customer') DEFAULT 'customer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ====================================================
-- 2. Material Categories
-- ====================================================
CREATE TABLE IF NOT EXISTS material_categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    category_name VARCHAR(50) UNIQUE NOT NULL
);

-- ====================================================
-- 3. Raw Materials
-- ====================================================
CREATE TABLE IF NOT EXISTS materials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    category_id INT,
    price_per_unit DECIMAL(10, 2) NOT NULL,
    unit VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES material_categories(id)
);

-- ====================================================
-- 4. Workers
-- ====================================================
CREATE TABLE IF NOT EXISTS workers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL,
    daily_wage DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ====================================================
-- 5. Projects
-- ====================================================
CREATE TABLE IF NOT EXISTS projects (
    id INT AUTO_INCREMENT PRIMARY KEY,
    project_name VARCHAR(150) NOT NULL,
    customer_name VARCHAR(100),
    area_sqft INT,
    status ENUM('Pending', 'In Progress', 'Completed') DEFAULT 'Pending',
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- ====================================================
-- 6. Project-Material Association
-- ====================================================
CREATE TABLE IF NOT EXISTS project_materials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    project_id INT,
    material_id INT,
    quantity DECIMAL(10, 2) NOT NULL,
    total_cost DECIMAL(12, 2),
    FOREIGN KEY (project_id) REFERENCES projects(id),
    FOREIGN KEY (material_id) REFERENCES materials(id)
);

-- ====================================================
-- 7. Project-Worker Association
-- ====================================================
CREATE TABLE IF NOT EXISTS project_workers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    project_id INT,
    worker_id INT,
    days INT NOT NULL DEFAULT 1,
    total_wage DECIMAL(12, 2),
    FOREIGN KEY (project_id) REFERENCES projects(id),
    FOREIGN KEY (worker_id) REFERENCES workers(id)
);

-- ====================================================
-- 8. Quotations
-- ====================================================
CREATE TABLE IF NOT EXISTS quotations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    project_id INT,
    quotation_number VARCHAR(50) UNIQUE NOT NULL,
    material_cost DECIMAL(15, 2) DEFAULT 0,
    labor_cost DECIMAL(15, 2) DEFAULT 0,
    total_cost DECIMAL(15, 2) DEFAULT 0,
    gst_amount DECIMAL(15, 2) DEFAULT 0,
    grand_total DECIMAL(15, 2) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id)
);

-- ====================================================
-- 9. Quotation Materials (for detailed breakdown)
-- ====================================================
CREATE TABLE IF NOT EXISTS quotation_materials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    quotation_id INT,
    material_id INT,
    quantity DECIMAL(10, 2) NOT NULL,
    unit_price DECIMAL(10, 2) NOT NULL,
    total_cost DECIMAL(12, 2),
    FOREIGN KEY (quotation_id) REFERENCES quotations(id),
    FOREIGN KEY (material_id) REFERENCES materials(id)
);

-- ====================================================
-- 10. Quotation Workers (for detailed breakdown)
-- ====================================================
CREATE TABLE IF NOT EXISTS quotation_workers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    quotation_id INT,
    worker_id INT,
    days INT NOT NULL,
    daily_wage DECIMAL(10, 2) NOT NULL,
    total_cost DECIMAL(12, 2),
    FOREIGN KEY (quotation_id) REFERENCES quotations(id),
    FOREIGN KEY (worker_id) REFERENCES workers(id)
);

-- ====================================================
-- Initial Data
-- ====================================================

-- Insert Material Categories
INSERT INTO material_categories (category_name) VALUES 
('Cement'),
('Steel'),
('Bricks'),
('Sand'),
('Aggregates'),
('Plumbing'),
('Electrical'),
('Flooring'),
('Painting'),
('Hardware');

-- Insert Default Admin User
INSERT INTO users (name, phone, password, role) VALUES 
('Admin', '1234567890', 'admin123', 'admin');

-- Insert Sample Materials
INSERT INTO materials (name, category_id, price_per_unit, unit) VALUES
('OPC Cement (50kg)', 1, 550, 'bag'),
('PPC Cement (50kg)', 1, 480, 'bag'),
('TMT Steel 12mm', 2, 65, 'kg'),
('TMT Steel 16mm', 2, 68, 'kg'),
('Red Bricks', 3, 8, 'piece'),
('Fly Ash Bricks', 3, 6, 'piece'),
('River Sand', 4, 45, 'cft'),
('M-Sand', 4, 40, 'cft'),
('20mm Aggregates', 5, 35, 'cft'),
('40mm Aggregates', 5, 30, 'cft');

-- Insert Sample Workers
INSERT INTO workers (name, role, daily_wage) VALUES
('Raju', 'Mason', 800),
('Kumar', 'Carpenter', 700),
('Suresh', 'Helper', 400),
('Mahesh', 'Electrician', 750),
('Ramesh', 'Plumber', 700);

-- Insert Sample Project
INSERT INTO projects (project_name, customer_name, area_sqft, status) VALUES
('Sharma Villa', 'Mr. Sharma', 2000, 'In Progress');

-- Assign materials to project
INSERT INTO project_materials (project_id, material_id, quantity, total_cost) VALUES
(1, 1, 100, 55000),
(1, 3, 500, 32500),
(1, 5, 10000, 80000);

-- Assign workers to project
INSERT INTO project_workers (project_id, worker_id, days, total_wage) VALUES
(1, 1, 30, 24000),
(1, 2, 30, 21000),
(1, 3, 30, 12000);

-- ====================================================
-- View for Project Costing
-- ====================================================
CREATE OR REPLACE VIEW project_costing_view AS
SELECT 
    p.id as project_id,
    p.project_name,
    p.customer_name,
    p.area_sqft,
    COALESCE(SUM(pm.total_cost), 0) as material_cost,
    COALESCE(SUM(pw.total_wage), 0) as labor_cost,
    COALESCE(SUM(pm.total_cost), 0) + COALESCE(SUM(pw.total_wage), 0) as total_cost
FROM projects p
LEFT JOIN project_materials pm ON p.id = pm.project_id
LEFT JOIN project_workers pw ON p.id = pw.project_id
GROUP BY p.id;

-- ====================================================
-- Sample Quotations
-- ====================================================
INSERT INTO quotations (project_id, quotation_number, material_cost, labor_cost, total_cost, gst_amount, grand_total) VALUES
(1, 'QTN-10000001', 167500, 57000, 224500, 40410, 264910);

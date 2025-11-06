# 🪴 Flask-Plant-Shop: Secure Plant Management & E-Commerce System 🚀

## 🌿 Overview
**Flask-Plant-Shop** is a secure, full-stack web application built using **Flask** and **MySQL** for managing a plant nursery’s inventory and facilitating customer orders.  
It implements a robust **role-based security model**, following best practices in application hardening, input validation, and database integrity.

---

## ✨ Key Features & Technical Highlights

| **Category** | **Features Implemented** |
|---------------|--------------------------|
| **Authentication & Security** | 🔐 Strong password hashing using **Werkzeug**.<br>🔒 **Role-Based Access Control (RBAC)** segregating Admin and Customer paths.<br>🚫 **Rate Limiting** on login route using **Flask-Limiter** to prevent brute-force attacks.<br>🛡️ **Session hardening** via **Flask-Talisman**. |
| **Admin Management** | ⚙️ Full **CRUD** functionality (Create, Read, Update) for plants, customers, and suppliers.<br>🔏 **Object-Based Access Control (OBAC)** ensures only authorized users can modify data. |
| **Database Integrity** | 💾 **Parameterized queries** (`%s` placeholders) prevent SQL Injection.<br>🧩 Server-side validation ensures correct data types (e.g., numeric checks for price and stock). |
| **E-Commerce Logic** | 🛍️ “Pending Order” (shopping cart) handled via session and DB.<br>💰 Ensures **price consistency** by storing product prices at purchase time in the `order_items` table. |

---

## 🛠️ Technology Stack

| **Component** | **Technology Used** |
|----------------|--------------------|
| **Backend Framework** | Python 3, Flask |
| **Database** | MySQL |
| **Security Libraries** | Flask-Talisman, Flask-Limiter, Werkzeug |
| **Database Connector** | mysql-connector-python |

---

## ⚙️ Setup and Installation

### 🧩 Prerequisites
- Python 3.x  
- MySQL Server (running locally on **localhost:3306**)

---

### 🗄️ 1. Database Configuration

1. Create a new database named **`plant_management`** in MySQL.  
2. Run your schema SQL script to create tables and define foreign keys.  
3. Ensure a MySQL user exists with these credentials (as used in `app.py`):

| Setting | Value |
|----------|--------|
| Host | localhost |
| User | root |
| Password | root |
| Database | plant_management |

---

### 🧰 2. Project Setup

```bash
# 1. Clone the repository
git clone https://github.com/YourUsername/Flask-Plant-Shop.git
cd Flask-Plant-Shop

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows, use: .\venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

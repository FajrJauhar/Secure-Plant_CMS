🪴 Flask-Plant-Shop: Secure Plant Management & E-Commerce System🚀 OverviewThis project is a secure, full-stack web application built using Flask and MySQL for managing a plant nursery's inventory and facilitating customer orders. It features a robust, role-based security model and demonstrates best practices in application hardening, input validation, and database integrity.✨ Key Features & Technical HighlightsCategoryFeatures ImplementedAuthentication & SecurityStrong password hashing using Werkzeug. Role-Based Access Control (UBAC) to segregate Admin and Customer paths. Rate Limiting (Flask-Limiter) on the login route to prevent brute-force attacks. Session hardening via Flask-Talisman.Admin ManagementGeneric Create, Read, and Update (CRUD) functionality for core tables (plant, customer, supplier). Object-Based Access Control (OBAC) ensures only authorized tables are editable.Database IntegrityParameterized Queries (%s placeholders) used everywhere to prevent SQL Injection. Server-side input validation (e.g., checking for numeric types on price/stock).E-Commerce Logic'Pending Order' (shopping cart) logic managed via the session and database, ensuring price data integrity by storing the price at the time of purchase in the order_items table.🛠️ Technology StackBackend Framework: Python 3, FlaskDatabase: MySQLSecurity: Flask-Talisman, Flask-Limiter, WerkzeugDatabase Connector: mysql-connector-python⚙️ Setup and InstallationPrerequisitesPython 3.xMySQL Server (running locally on localhost:3306)1. Database ConfigurationCreate a database named plant_management and run your schema SQL scripts (table creation, foreign keys). Ensure a user exists with the following credentials (matching DB_CONFIG in app.py):SettingValueHostlocalhostUserrootPasswordrootDatabaseplant_management2. Project SetupBash# 1. Clone the repository
git clone https://github.com/YourUsername/Flask-Plant-Shop.git
cd Flask-Plant-Shop

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows, use: .\venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
3. Running the ApplicationBash# Set Flask to run in development mode (optional)
export FLASK_ENV=development 

# Run the app
python app.py
The application will be accessible at http://127.0.0.1:5000/.🔒 Access Credentials (Initial State)Admin Login: You will need to manually insert an Admin user into the customer table, setting the role column to 'admin' and generating a hashed password.Customer Login: Use the /register route to create a new customer account.🤝 ContributionThis project was developed as a demonstration of secure Flask development practices. Contributions and suggestions are welcome!

from flask import Flask, abort, redirect, url_for, render_template, request, session
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash
import mysql.connector
from mysql.connector import Error
from datetime import timedelta # <-- ADDED for session timeout

# --- 1. APP CONFIGURATION ---
app = Flask(__name__)
app.secret_key ='9df31cad3eb2f66386575da6dd6641ae0738d498bc5f21f00888a7536d54c038'

# Set session to expire after 30 minutes of inactivity
app.permanent_session_lifetime = timedelta(minutes=30) 

# Talisman/CSP Configuration
Talisman(app, 
         content_security_policy=False, 
         force_https=False,
         strict_transport_security=True,
         session_cookie_secure=True)

# Limiter/Rate Limiting Configuration
limiter = Limiter(
    key_prefix="rate_limit", 
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"] 
)

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root', 
    'database': 'plant_management'
}

# --- 2. GLOBAL UTILITIES & SCHEMAS ---

def get_db_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# OBAC Configuration
ALLOWED_ADMIN_TABLES = ['plant', 'customer', 'supplier', 'order', 'order_items']
TABLE_SCHEMAS = {
    'plant': ['name', 'type', 'price', 'stock_quantity', 'supplier_id', 'category'],
    'customer': ['name', 'email', 'phone', 'address'], 
    'supplier': ['name', 'contact_name', 'phone', 'email']}
TABLE_PKS = {
    'plant': 'plant_id',
    'customer': 'customer_id',
    'supplier': 'supplier_id',
    'order': 'order_id',
    'order_items': 'order_item_id' 
}

# --- 3. CUSTOMER AUTHENTICATION ROUTES ---

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        phone = request.form['phone'].strip()
        address = request.form['address'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match.")

        hashed_password = generate_password_hash(password) 
        
        connection = get_db_connection()
        if connection is None:
            return render_template('register.html', error="Database connection failed.")
        
        cursor = connection.cursor() 
        
        try:
            # Check for existing email (Data Integrity Check)
            cursor.execute("SELECT customer_id FROM customer WHERE email = %s", (email,))
            if cursor.fetchone():
                return render_template('register.html', error="An account with this email already exists.")
            
            query = """
            INSERT INTO customer (name, phone, email, password_hash, role, address)
            VALUES (%s, %s, %s, %s, 'customer', %s)
            """
            cursor.execute(query, (name, phone, email, hashed_password, address))
            connection.commit()
            return redirect(url_for('login', message="Registration successful! Please log in."))
            
        except Exception as e:
            error_msg = f"Database Error: {e}"
            print(f"Registration error: {error_msg}")
            connection.rollback()
            return render_template('register.html', error="Registration failed due to a database error.")
            
        finally:
            if cursor: cursor.close()
            if connection and connection.is_connected(): connection.close()
            
    return render_template('register.html', error=None, message=None)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('5 per minute ;10 per hour')
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        connection = get_db_connection()
        if connection is None:
            return render_template('login.html', error="Database connection failed.")
        
        cursor = connection.cursor(dictionary=True)
        
        try:
            query = "SELECT customer_id, name, role, password_hash FROM customer WHERE name = %s OR email = %s;"
            cursor.execute(query, (username, username))
            user = cursor.fetchone() 
            
            # Checks if user exists AND password hash matches
            if user and user.get('password_hash') and check_password_hash(user['password_hash'], password):
                
                session['user_id'] = user['customer_id']
                session['user_role'] = user['role']
                session.permanent = True # <-- Enables Session Timeout
                
                # Role-Based Redirection
                if user['role'] == 'admin':
                    return redirect(url_for('admin_page')) 
                else:
                    return redirect(url_for('customer_home'))
            else:
                return render_template('login.html', error="Invalid username or password.")
                
        except Exception as e:
            print(f"Login error: {e}")
            return render_template('login.html', error="An unexpected error occurred during login.")
            
        finally:
            if cursor: cursor.close()
            if connection and connection.is_connected(): connection.close()
            
    message = request.args.get('message')
    return render_template('login.html', error=None, message=message)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_role', None)
    session.pop('pending_order_id', None)
    return redirect(url_for('login', message="You have been successfully logged out."))

# --- 4. ADMIN ROUTES ---

@app.route('/admin')
def admin_page():
    if session.get('user_role') != 'admin':
        return redirect(url_for('login'))
        
    connection = get_db_connection()
    if connection is None:
        return "Database Connection Error.", 500
        
    cursor = connection.cursor(dictionary=True)
    tablename = []
    
    try:
        # Fetching all tables and filtering by ALLOWED_ADMIN_TABLES
        cursor.execute("SHOW TABLES;")
        table_raw = cursor.fetchall()
        
        if table_raw:
            key = list(table_raw[0].keys())[0]
            all_tables = [table[key] for table in table_raw]
            tablename = [t for t in all_tables if t in ALLOWED_ADMIN_TABLES]
            
        return render_template('admin_page.html', tables=tablename)
        
    except Error as e:
        print(f"Error executing Query: {e}")
        return "Database query failed. Please check for server logs.", 500
        
    finally:
        if cursor: cursor.close()
        if connection and connection.is_connected(): connection.close()

@app.route('/admin/view/<string:table_name>')
def admin_generic_view(table_name):
    # OBAC: Check if the table is whitelisted
    if session.get('user_role') != 'admin' or table_name not in ALLOWED_ADMIN_TABLES:
        return redirect(url_for('login')) 

    connection = get_db_connection()
    if connection is None:
        return "Database connection error.", 500

    cursor = connection.cursor(dictionary=True)
    data = []
    headers = []
    
    try:
        query = f"SELECT * FROM `{table_name}`;"
        cursor.execute(query)
        data = cursor.fetchall()
        
        if data:
            headers = list(data[0].keys())
        
        return render_template('admin_table_view.html',
                               table_name=table_name.replace('_', ' ').title(), 
                               headers=headers, 
                               data=data,
                               pk_column=TABLE_PKS.get(table_name)) # Pass PK for edit links
    
    except Exception as e:
        print(f"Error fetching data from {table_name}: {e}")
        return f"Error executing query for {table_name}.", 500
        
    finally:
        if cursor: cursor.close()
        if connection and connection.is_connected(): connection.close()

@app.route('/admin/add/<string:table_name>', methods=['GET', 'POST'])
def admin_add_generic(table_name):
    if session.get('user_role') != 'admin' or table_name not in TABLE_SCHEMAS:
        return redirect(url_for('login')) 

    fields = TABLE_SCHEMAS[table_name]
    connection = get_db_connection()
    
    if request.method == 'POST':
        values = []
        cursor = None
        
        try:
            # --- 1. INPUT VALIDATION & SANITIZATION ---
            for field in fields:
                value = request.form[field]
                
                # Numeric type casting and validation
                if field in ['price', 'stock_quantity']:
                    value = float(value) if '.' in value else int(value)
                
                # String stripping
                if isinstance(value, str):
                    value = value.strip()
                
                values.append(value)
            
            # --- 2. DATABASE EXECUTION (Proceed only if validation succeeds) ---
            if connection is None:
                return "Database Connection Error.", 500

            columns = ', '.join(fields)
            placeholders = ', '.join(['%s'] * len(fields)) 
            query = f"INSERT INTO `{table_name}` ({columns}) VALUES ({placeholders})"

            cursor = connection.cursor()
            cursor.execute(query, tuple(values))
            connection.commit()
            
            return redirect(url_for('admin_generic_view', 
                                    table_name=table_name, 
                                    message=f"{table_name.title()} added successfully!"))
        
        # --- 3. ERROR HANDLING ---

        except ValueError:
            connection.rollback()
            error_msg = "Invalid data format. Please ensure **Price** and **Stock Quantity** are valid numbers."
            return render_template('admin_add_generic.html', 
                                   table_name=table_name.title(), 
                                   fields=fields, 
                                   error=error_msg)
        
        except Exception as e:
            connection.rollback()
            error_msg = f"Database error: {e}"
            print(f"Insertion error: {error_msg}")
            return render_template('admin_add_generic.html', 
                                   table_name=table_name.title(), 
                                   fields=fields, 
                                   error="Database Error. Check server logs.")
            
        finally:
            if cursor: cursor.close()
            if connection and connection.is_connected(): connection.close()
            
    # Handle GET request (Show Form)
    return render_template('admin_add_generic.html', 
                            table_name=table_name.title(), 
                            fields=fields, 
                            error=None, message=request.args.get('message'))

@app.route('/admin/edit/<string:table_name>/<int:record_id>', methods=['GET', 'POST'])
def admin_edit_generic(table_name, record_id):
    if session.get('user_role') != 'admin' or table_name not in TABLE_SCHEMAS or table_name not in TABLE_PKS:
        return redirect(url_for('login'))
        
    fields = TABLE_SCHEMAS[table_name]
    pk_column = TABLE_PKS[table_name]
    connection = get_db_connection()
    cursor = None 
    
    if connection is None:
        return "Database connection error.", 500
        
    cursor = connection.cursor(dictionary=True)

    try:
        if request.method == 'POST':
            
            values = []
            
            # --- 1. Validation Block ---
            try:
                for field in fields:
                    value = request.form[field]
                    
                    if field in ['price', 'stock_quantity']:
                        value = float(value) if '.' in value else int(value)
                    
                    if isinstance(value, str):
                        value = value.strip()
                    
                    values.append(value)
            
            except ValueError:
                connection.rollback()
                # Re-fetch the record to re-render the edit form with current data
                cursor.execute(f"SELECT * FROM `{table_name}` WHERE `{pk_column}` = %s", (record_id,))
                record = cursor.fetchone()
                
                return render_template('admin_edit_generic.html', 
                                       table_name=table_name.title(), 
                                       record_id=record_id,
                                       fields=fields,
                                       record=record,
                                       error="Invalid data format. Please ensure Price and Stock Quantity are valid numbers.")

            # --- 2. Database Execution Block ---
            
            set_clauses = [f"`{field}` = %s" for field in fields]
            set_clause_str = ', '.join(set_clauses)
            
            query = f"UPDATE `{table_name}` SET {set_clause_str} WHERE `{pk_column}` = %s"
            
            cursor.execute(query, tuple(values + [record_id]))
            connection.commit()
            
            message = f"{table_name.title()} ID {record_id} updated successfully!"
            return redirect(url_for('admin_generic_view', table_name=table_name, message=message))
            
        # --- GET: Fetch existing record (SELECT) ---
        
        select_query = f"SELECT * FROM `{table_name}` WHERE `{pk_column}` = %s"
        cursor.execute(select_query, (record_id,))
        record = cursor.fetchone()
        
        if not record:
            abort(404)

        return render_template('admin_edit_generic.html', 
                               table_name=table_name.title(), 
                               record_id=record_id,
                               fields=fields,
                               record=record,
                               error=None)
                               
    except Exception as e:
        connection.rollback()
        error_msg = f"Error processing update/fetch for {table_name}: {e}"
        print(error_msg)
        return redirect(url_for('admin_generic_view', table_name=table_name, error="Unexpected database error during edit."))
            
    finally:
        if cursor: cursor.close()
        if connection and connection.is_connected(): connection.close()

# --- 5. CUSTOMER E-COMMERCE ROUTES ---

@app.route('/shop')
def customer_home():
    user_id = session.get('user_id')
    user_role = session.get('user_role')
    
    if not user_id or user_role != 'customer':
        return redirect(url_for('login'))

    connection = get_db_connection()
    if connection is None:
        return render_template('customer_home.html', error="Database connection failed.")

    cursor = connection.cursor(dictionary=True)
    plants = []
    
    try:
        # Fetch all plants available for purchase
        query = "SELECT plant_id, name, type, price, stock_quantity, category FROM plant WHERE stock_quantity > 0 ORDER BY name ASC;"
        cursor.execute(query)
        plants = cursor.fetchall()
        
        return render_template('customer_home.html', 
                               plants=plants, 
                               error=request.args.get('error'), 
                               message=request.args.get('message'))
        
    except Exception as e:
        print(f"Error fetching plant data: {e}")
        return render_template('customer_home.html', error="Error loading products.")
        
    finally:
        if cursor: cursor.close()
        if connection and connection.is_connected(): connection.close()

@app.route('/add-to-cart/<int:plant_id>', methods=['POST'])
def add_to_cart(plant_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login')) 

    # Assuming quantity is 1 for a basic "Add to Cart" click
    quantity = 1 
    
    connection = get_db_connection()
    if connection is None:
        return redirect(url_for('customer_home', error="Database connection failed."))

    cursor = connection.cursor()
    cursor_dict = connection.cursor(dictionary=True)
    
    try:
        # 1. Get Plant Price and Stock
        cursor_dict.execute("SELECT price, stock_quantity FROM plant WHERE plant_id = %s", (plant_id,))
        plant_info = cursor_dict.fetchone()
        
        if not plant_info or plant_info['stock_quantity'] < quantity:
            return redirect(url_for('customer_home', error="Selected plant is out of stock or does not exist."))
            
        plant_price = plant_info['price']
        
        # 2. Find or Create a Pending Order
        order_id = session.get('pending_order_id')
        
        if not order_id:
            # Create a new 'Pending' order
            insert_order_query = "INSERT INTO `order` (customer_id, order_date, total_amount, status) VALUES (%s, NOW(), 0.00, 'Pending')"
            cursor.execute(insert_order_query, (user_id,))
            order_id = cursor.lastrowid
            session['pending_order_id'] = order_id
        
        # 3. Add/Update Item in order_items table
        check_item_query = "SELECT quantity FROM order_items WHERE order_id = %s AND plant_id = %s"
        cursor.execute(check_item_query, (order_id, plant_id))
        existing_item = cursor.fetchone()
        
        if existing_item:
            # Item exists: update quantity
            new_quantity = existing_item[0] + quantity
            update_item_query = "UPDATE order_items SET quantity = %s WHERE order_id = %s AND plant_id = %s"
            cursor.execute(update_item_query, (new_quantity, order_id, plant_id))
        else:
            # Item is new: insert new item
            insert_item_query = "INSERT INTO order_items (order_id, plant_id, quantity, price) VALUES (%s, %s, %s, %s)"
            cursor.execute(insert_item_query, (order_id, plant_id, quantity, plant_price))

        # 4. Update the Order's total_amount (Recalculate total)
        update_total_query = """
        UPDATE `order` o
        SET total_amount = (
            SELECT SUM(quantity * price)
            FROM order_items oi
            WHERE oi.order_id = o.order_id
        )
        WHERE o.order_id = %s
        """
        cursor.execute(update_total_query, (order_id,))

        connection.commit()
        
        return redirect(url_for('customer_home', message="Plant added to cart!"))

    except Exception as e:
        connection.rollback()
        error_msg = f"Cart error: {e}"
        print(f"Cart error: {error_msg}")
        return redirect(url_for('customer_home', error="Failed to add item to cart. Please check server logs."))
        
    finally:
        if cursor: cursor.close()
        if cursor_dict: cursor_dict.close()
        if connection and connection.is_connected(): connection.close()

@app.route('/my-orders')
def customer_view_orders():
    user_id = session.get('user_id') 
    if not user_id:
        return redirect(url_for('login'))

    connection = get_db_connection()
    # ... (connection error check and database logic as before) ...
    # ... (omitted for brevity) ...
    return "Orders view placeholder"

@app.route('/my-orders/<int:order_id>')
def customer_order_details(order_id):
    user_id = session.get('user_id')
    # ... (connection error check and database logic as before) ...
    # ... (omitted for brevity) ...
    return "Order details view placeholder"

# --- 6. RUN THE APP ---

if __name__ == '__main__':
    initial_conn = get_db_connection()
    if initial_conn:
        print("Initial connection test successful.")
        initial_conn.close()
    else:
        print("Initial connection test FAILED.")

    app.run(debug=True)
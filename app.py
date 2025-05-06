import mysql.connector
import os
import re
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64
from datetime import datetime
import csv
from difflib import SequenceMatcher

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey123')

# Database configuration
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', '1234567890'),
    'database': os.getenv('DB_NAME', 'iwb')
}

def get_db():
    conn = mysql.connector.connect(**db_config)
    return conn

# Database initialization
def init_db():
    conn = get_db()
    c = conn.cursor()
    # Create tables if they don't exist
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE,
        password VARCHAR(255),
        user_type VARCHAR(50),
        tenant VARCHAR(50),
        mfa_code VARCHAR(10)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255),
        type VARCHAR(50),
        price DECIMAL(10, 2),
        tenant VARCHAR(50),
        quantity INT,
        `condition` VARCHAR(50)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS sales (
        id INT AUTO_INCREMENT PRIMARY KEY,
        product_id INT,
        quantity INT,
        total DECIMAL(10, 2),
        date VARCHAR(50),
        tenant VARCHAR(50),
        user_id INT,
        FOREIGN KEY (product_id) REFERENCES products(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS queries (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255),
        email VARCHAR(255),
        message TEXT,
        status VARCHAR(50),
        response TEXT,
        date VARCHAR(50),
        tenant VARCHAR(50),
        user_id INT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS income_statements (
        id INT AUTO_INCREMENT PRIMARY KEY,
        month VARCHAR(50),
        revenue DECIMAL(10, 2),
        expenses DECIMAL(10, 2),
        profit DECIMAL(10, 2),
        tenant VARCHAR(50)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS query_templates (
        id INT AUTO_INCREMENT PRIMARY KEY,
        keyword VARCHAR(255),
        response TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS cards (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        card_number VARCHAR(255),
        expiry VARCHAR(10),
        cvv VARCHAR(10),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')

    # Delete dependent records from sales before deleting products
    c.execute('''DELETE s FROM sales s
                 JOIN products p ON s.product_id = p.id
                 WHERE p.tenant = %s''', ('iwb',))
    # Now safe to delete products
    c.execute("DELETE FROM products WHERE tenant = 'iwb'")
    sample_products = [
        # RAM (6)
        ('8GB DDR4 RAM 2666MHz', 'RAM', 200.0, 'iwb', 10, 'new'),
        ('16GB DDR4 RAM 3200MHz', 'RAM', 500.0, 'iwb', 10, 'new'),
        ('32GB DDR4 RAM 3600MHz', 'RAM', 800.0, 'iwb', 8, 'new'),
        ('8GB DDR4 RAM 2666MHz', 'RAM', 150.0, 'iwb', 15, 'pre-used'),
        ('16GB DDR4 RAM 3200MHz', 'RAM', 300.0, 'iwb', 8, 'pre-used'),
        ('32GB DDR4 RAM 3600MHz', 'RAM', 600.0, 'iwb', 6, 'pre-used'),
        # Motherboard Components (6)
        ('ATX Motherboard Intel', 'Motherboard Component', 1000.0, 'iwb', 5, 'new'),
        ('Micro ATX Motherboard AMD', 'Motherboard Component', 800.0, 'iwb', 5, 'new'),
        ('Mini ITX Motherboard Intel', 'Motherboard Component', 1200.0, 'iwb', 5, 'new'),
        ('ATX Motherboard Intel', 'Motherboard Component', 700.0, 'iwb', 4, 'pre-used'),
        ('Micro ATX Motherboard AMD', 'Motherboard Component', 600.0, 'iwb', 4, 'pre-used'),
        ('Mini ITX Motherboard Intel', 'Motherboard Component', 900.0, 'iwb', 4, 'pre-used'),
        # Hard Drives (6)
        ('1TB HDD 7200RPM', 'Hard Drive', 500.0, 'iwb', 15, 'new'),
        ('2TB HDD 5400RPM', 'Hard Drive', 700.0, 'iwb', 15, 'new'),
        ('500GB HDD 7200RPM', 'Hard Drive', 300.0, 'iwb', 15, 'new'),
        ('1TB HDD 7200RPM', 'Hard Drive', 350.0, 'iwb', 12, 'pre-used'),
        ('2TB HDD 5400RPM', 'Hard Drive', 500.0, 'iwb', 12, 'pre-used'),
        ('500GB HDD 7200RPM', 'Hard Drive', 200.0, 'iwb', 12, 'pre-used'),
        # For tenant iwc
        ('8GB DDR4 RAM', 'RAM', 250.0, 'iwc', 10, 'new'),
    ]
    c.executemany('INSERT INTO products (name, type, price, tenant, quantity, `condition`) VALUES (%s, %s, %s, %s, %s, %s)', sample_products)

    # Insert sample income statements
    c.execute("DELETE FROM income_statements WHERE tenant = 'iwb'")
    sample_statements = [
        ('2025-01', 10000.0, 6000.0, 4000.0, 'iwb'),
        ('2025-02', 12000.0, 7000.0, 5000.0, 'iwb'),
    ]
    c.executemany('INSERT INTO income_statements (month, revenue, expenses, profit, tenant) VALUES (%s, %s, %s, %s, %s)', sample_statements)

    # Insert sample query templates
    c.execute("DELETE FROM query_templates")
    sample_templates = [
        ('price', 'Please check our product listings for current prices.'),
        ('availability', 'All products are currently in stock unless otherwise noted.'),
    ]
    c.executemany('INSERT INTO query_templates (keyword, response) VALUES (%s, %s)', sample_templates)

    conn.commit()
    conn.close()

# Role-based access decorator
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in.')
                return redirect(url_for('login'))
            conn = get_db()
            c = conn.cursor()
            c.execute('SELECT user_type, tenant, username FROM users WHERE id = %s', (session['user_id'],))
            user = c.fetchone()
            conn.close()
            if not user:
                flash('User not found.')
                return redirect(url_for('login'))
            print(f"Role check: user_id={session['user_id']}, user_type={user[0]}, tenant={user[1]}, username={user[2]}")
            if user[0] not in roles:
                flash('Unauthorized access.')
                return redirect(url_for('index'))
            session['tenant'] = user[1]
            session['user_type'] = user[0]
            session['username'] = user[2]
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Simulated MFA check
def mfa_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'mfa_verified' not in session or not session['mfa_verified']:
            flash('MFA verification required.')
            return redirect(url_for('mfa'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    print(f"Index accessed: session={session}")
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT MAX(id) as id, name, `condition`, type, AVG(price) as avg_price, SUM(quantity) as total_quantity
        FROM products 
        WHERE tenant = 'iwb'
        GROUP BY name, `condition`, type
        ORDER BY type, name, `condition`
    """)
    products = c.fetchall()
    conn.close()
    expected_rows = 18
    if len(products) != expected_rows:
        flash(f'Error: Expected {expected_rows} products, but retrieved {len(products)}.', 'error')
    # Pass a flag to the template to indicate if the user is logged in
    is_logged_in = 'username' in session
    return render_template('index.html', products=products, is_logged_in=is_logged_in)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        if not username or not password or not email:
            flash('All fields are required.')
            return redirect(url_for('register'))
        if not re.match(r'^[a-zA-Z0-9_]{4,20}$', username):
            flash('Username must be 4-20 characters, using letters, numbers, or underscores.')
            return redirect(url_for('register'))
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Invalid email format.')
            return redirect(url_for('register'))
        conn = get_db()
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password, user_type, tenant, mfa_code) VALUES (%s, %s, %s, %s, %s)',
                     (username, generate_password_hash(password), 'customer', 'iwb', '123456'))
            conn.commit()
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('Username already exists.')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_type = request.form['user_type']
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            print(f"Login: username={username}, user_type={user[3]}, user_type_input={user_type}")
            if (user_type == 'admin' and user[3] in ['sales', 'finance', 'developer', 'investor']) or \
               (user_type == 'customer' and user[3] == 'customer'):
                session['user_id'] = user[0]
                session['user_type'] = user[3]
                session['username'] = user[1]
                session['tenant'] = user[5]
                session['mfa_verified'] = False
                session['cart'] = {}
                print(f"Session set: user_id={user[0]}, user_type={user[3]}, username={user[1]}, tenant={user[5]}")
                return redirect(url_for('mfa'))
            else:
                flash('Invalid user type for this account.')
        else:
            flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if request.method == 'POST':
        mfa_code = request.form['mfa_code']
        if mfa_code == '123456':
            session['mfa_verified'] = True
            return redirect(url_for('index'))
        flash('Invalid MFA code.')
    return render_template('mfa.html')

@app.route('/logout')
def logout():
    print(f"Logout: session before clear={session}")
    session.clear()
    print(f"Logout: session after clear={session}")
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/cart', methods=['GET', 'POST'])
@role_required('customer')
@mfa_required
def cart():
    if 'cart' not in session:
        session['cart'] = {}
    
    conn = get_db()
    c = conn.cursor()
    
    if request.method == 'POST':
        action = request.form.get('action')
        product_id = request.form.get('product_id')
        quantity = request.form.get('quantity', type=int)
        
        if action == 'add':
            if not product_id or not quantity or quantity <= 0:
                flash('Invalid product or quantity.')
                return redirect(url_for('cart'))
            c.execute('SELECT quantity FROM products WHERE id = %s AND tenant = %s', (product_id, 'iwb'))
            product = c.fetchone()
            if not product:
                flash('Product not found.')
                return redirect(url_for('cart'))
            if product[0] < quantity:
                flash(f'Insufficient stock. Only {product[0]} units available.')
                return redirect(url_for('cart'))
            session['cart'][product_id] = session['cart'].get(product_id, 0) + quantity
            session.modified = True
            flash('Product added to cart.')
        
        elif action == 'update':
            if product_id in session['cart'] and quantity >= 0:
                c.execute('SELECT quantity FROM products WHERE id = %s', (product_id,))
                product = c.fetchone()
                if product and quantity > product[0]:
                    flash(f'Insufficient stock. Only {product[0]} units available.')
                    return redirect(url_for('cart'))
                if quantity == 0:
                    del session['cart'][product_id]
                else:
                    session['cart'][product_id] = quantity
                session.modified = True
                flash('Cart updated.')
        
        elif action == 'remove':
            if product_id in session['cart']:
                del session['cart'][product_id]
                session.modified = True
                flash('Product removed from cart.')
        
        return redirect(url_for('cart'))
    
    cart_items = []
    total = 0
    for product_id, quantity in session['cart'].items():
        c.execute('SELECT id, name, type, price, quantity, `condition` FROM products WHERE id = %s', (product_id,))
        product = c.fetchone()
        if product:
            cart_items.append({
                'id': product[0],
                'name': product[1],
                'type': product[2],
                'price': product[3],
                'quantity': quantity,
                'condition': product[5],
                'subtotal': product[3] * quantity
            })
            total += product[3] * quantity
    
    conn.close()
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/card', methods=['GET', 'POST'])
@role_required('customer')
@mfa_required
def card():
    if request.method == 'POST':
        card_number = request.form['card_number']
        expiry = request.form['expiry']
        cvv = request.form['cvv']
        if not re.match(r'^\d{16}$', card_number):
            flash('Card number must be 16 digits.')
            return redirect(url_for('card'))
        if not re.match(r'^(0[1-9]|1[0-2])/[0-9]{2}$', expiry):
            flash('Expiry must be in MM/YY format.')
            return redirect(url_for('card'))
        if not re.match(r'^\d{3}$', cvv):
            flash('CVV must be 3 digits.')
            return redirect(url_for('card'))
        conn = get_db()
        c = conn.cursor()
        hashed_card = generate_password_hash(card_number[-4:])
        c.execute('INSERT INTO cards (user_id, card_number, expiry, cvv) VALUES (%s, %s, %s, %s)',
                 (session['user_id'], hashed_card, expiry, cvv))
        conn.commit()
        conn.close()
        flash('Card added successfully.')
        return redirect(url_for('cart'))
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, card_number, expiry FROM cards WHERE user_id = %s', (session['user_id'],))
    cards = c.fetchall()
    conn.close()
    return render_template('card.html', cards=cards)

@app.route('/products', methods=['GET', 'POST'])
@role_required('developer')
@mfa_required
def manage_products():
    if request.method == 'POST':
        name = request.form['name']
        type_ = request.form['type']
        condition = request.form['condition']
        try:
            price = float(request.form['price'])
            quantity = int(request.form['quantity'])
            if price < 0 or quantity < 0:
                flash('Price and quantity cannot be negative.')
                return redirect(url_for('manage_products'))
        except ValueError:
            flash('Invalid price or quantity.')
            return redirect(url_for('manage_products'))
        if condition not in ['new', 'pre-used']:
            flash('Condition must be "new" or "pre-used".')
            return redirect(url_for('manage_products'))
        tenant = session['tenant']
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO products (name, type, price, tenant, quantity, `condition`) VALUES (%s, %s, %s, %s, %s, %s)',
                 (name, type_, price, tenant, quantity, condition))
        conn.commit()
        conn.close()
        flash('Product added.')
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM products WHERE tenant = %s', (session['tenant'],))
    products = c.fetchall()
    conn.close()
    return render_template('products.html', products=products)

@app.route('/sales', methods=['GET', 'POST'])
@role_required('sales')
@mfa_required
def sales():
    if request.method == 'POST':
        product_id = request.form['product_id']
        try:
            quantity = int(request.form['quantity'])
            if quantity <= 0:
                flash('Quantity must be positive.')
                return redirect(url_for('sales'))
        except ValueError:
            flash('Invalid quantity.')
            return redirect(url_for('sales'))
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT price, quantity FROM products WHERE id = %s AND tenant = %s', (product_id, session['tenant']))
        product = c.fetchone()
        if not product:
            flash('Product not found.')
            conn.close()
            return redirect(url_for('sales'))
        
        if product[1] < quantity:
            flash(f'Insufficient stock. Only {product[1]} units available.')
            conn.close()
            return redirect(url_for('sales'))
        
        total = product[0] * quantity
        date = datetime.now().strftime('%Y-%m-%d')
        c.execute('INSERT INTO sales (product_id, quantity, total, date, tenant, user_id) VALUES (%s, %s, %s, %s, %s, %s)',
                 (product_id, quantity, total, date, session['tenant'], session['user_id']))
        c.execute('UPDATE products SET quantity = quantity - %s WHERE id = %s', (quantity, product_id))
        conn.commit()
        conn.close()
        flash('Sale recorded.')
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT s.*, p.name FROM sales s JOIN products p ON s.product_id = p.id WHERE s.tenant = %s', (session['tenant'],))
    sales = c.fetchall()
    c.execute('SELECT * FROM products WHERE tenant = %s', (session['tenant'],))
    products = c.fetchall()
    conn.close()
    return render_template('sales.html', sales=sales, products=products)

@app.route('/purchase', methods=['GET', 'POST'])
@role_required('customer')
@mfa_required
def purchase():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, card_number, expiry FROM cards WHERE user_id = %s', (session['user_id'],))
    cards = c.fetchall()
    
    if 'cart' not in session or not session['cart']:
        flash('Your cart is empty.')
        conn.close()
        return redirect(url_for('cart'))
    
    cart_items = []
    total = 0
    for product_id, quantity in session['cart'].items():
        c.execute('SELECT id, name, type, price, quantity, `condition` FROM products WHERE id = %s AND tenant = %s', (product_id, 'iwb'))
        product = c.fetchone()
        if product:
            cart_items.append({
                'id': product[0],
                'name': product[1],
                'type': product[2],
                'price': product[3],
                'quantity': quantity,
                'condition': product[5],
                'subtotal': product[3] * quantity
            })
            total += product[3] * quantity
    
    if request.method == 'POST':
        card_id = request.form.get('card_id')
        if not card_id and not (request.form.get('card_number') and request.form.get('expiry') and request.form.get('cvv')):
            flash('Please select a card or enter new card details.')
            conn.close()
            return redirect(url_for('purchase'))
        
        if not card_id:
            card_number = request.form['card_number']
            expiry = request.form['expiry']
            cvv = request.form['cvv']
            if not re.match(r'^\d{16}$', card_number):
                flash('Card number must be 16 digits.')
                conn.close()
                return redirect(url_for('purchase'))
            if not re.match(r'^(0[1-9]|1[0-2])/[0-9]{2}$', expiry):
                flash('Expiry must be in MM/YY format.')
                conn.close()
                return redirect(url_for('purchase'))
            if not re.match(r'^\d{3}$', cvv):
                flash('CVV must be 3 digits.')
                conn.close()
                return redirect(url_for('purchase'))
            hashed_card = generate_password_hash(card_number[-4:])
            c.execute('INSERT INTO cards (user_id, card_number, expiry, cvv) VALUES (%s, %s, %s, %s)',
                     (session['user_id'], hashed_card, expiry, cvv))
            conn.commit()
        
        # Validate stock for all cart items
        for item in cart_items:
            c.execute('SELECT quantity FROM products WHERE id = %s', (item['id'],))
            stock = c.fetchone()[0]
            if stock < item['quantity']:
                flash(f'Insufficient stock for {item["name"]}. Only {stock} units available.')
                conn.close()
                return redirect(url_for('cart'))
        
        # Simulate payment processing
        payment_success = True
        if payment_success:
            date = datetime.now().strftime('%Y-%m-%d')
            for item in cart_items:
                total = item['price'] * item['quantity']
                c.execute('INSERT INTO sales (product_id, quantity, total, date, tenant, user_id) VALUES (%s, %s, %s, %s, %s, %s)',
                         (item['id'], item['quantity'], total, date, 'iwb', session['user_id']))
                c.execute('UPDATE products SET quantity = quantity - %s WHERE id = %s', (item['quantity'], item['id']))
            conn.commit()
            session['cart'] = {}
            session.modified = True
            flash('Payment completed. Purchase recorded.')
            conn.close()
            return redirect(url_for('index'))
        else:
            flash('Payment failed. Please try again.')
            conn.close()
            return redirect(url_for('purchase'))
    
    try:
        c.execute('SELECT s.*, p.name FROM sales s JOIN products p ON s.product_id = p.id WHERE s.user_id = %s', (session['user_id'],))
        purchases = c.fetchall()
    except mysql.connector.Error as e:
        print(f"Database error in purchase route: {e}")
        flash('Unable to retrieve purchase history due to a database issue. Please contact support.')
        purchases = []
    conn.close()
    return render_template('purchase.html', cart_items=cart_items, total=total, cards=cards, purchases=purchases)

@app.route('/income_statement')
@role_required('finance', 'investor')
@mfa_required
def income_statement():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT month, revenue, expenses, profit FROM income_statements WHERE tenant = %s', (session['tenant'],))
    statements = c.fetchall()
    
    months = [s[0] for s in statements]
    revenues = [s[1] for s in statements]
    expenses = [s[2] for s in statements]
    profits = [s[3] for s in statements]
    
    plt.figure(figsize=(10, 5))
    plt.bar(months, profits, color='green')
    plt.xlabel('Month')
    plt.ylabel('Profit (M)')
    plt.title('Monthly Profit')
    img_profit = io.BytesIO()
    plt.savefig(img_profit, format='png')
    img_profit.seek(0)
    profit_url = base64.b64encode(img_profit.getvalue()).decode()
    plt.close()
    
    plt.figure(figsize=(10, 5))
    plt.plot(months, revenues, label='Revenue', marker='o')
    plt.plot(months, expenses, label='Expenses', marker='o')
    plt.xlabel('Month')
    plt.ylabel('Amount (M)')
    plt.title('Revenue vs Expenses')
    plt.legend()
    img_rev_exp = io.BytesIO()
    plt.savefig(img_rev_exp, format='png')
    img_rev_exp.seek(0)
    rev_exp_url = base64.b64encode(img_rev_exp.getvalue()).decode()
    plt.close()
    
    conn.close()
    return render_template('income_statement.html', statements=statements, profit_url=profit_url, rev_exp_url=rev_exp_url)

@app.route('/generate_statement', methods=['POST'])
@role_required('finance')
@mfa_required
def generate_statement():
    month = request.form['month']
    if not re.match(r'^\d{4}-\d{2}$', month):
        flash('Month must be in YYYY-MM format.')
        return redirect(url_for('income_statement'))
    try:
        revenue = float(request.form['revenue'])
        expenses = float(request.form['expenses'])
        if revenue < 0 or expenses < 0:
            flash('Revenue and expenses cannot be negative.')
            return redirect(url_for('income_statement'))
    except ValueError:
        flash('Invalid revenue or expenses.')
        return redirect(url_for('income_statement'))
    profit = revenue - expenses
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO income_statements (month, revenue, expenses, profit, tenant) VALUES (%s, %s, %s, %s, %s)',
             (month, revenue, expenses, profit, session['tenant']))
    conn.commit()
    conn.close()
    flash('Income statement generated.')
    return redirect(url_for('income_statement'))

@app.route('/query', methods=['GET', 'POST'])
def query():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Invalid email format.')
            return redirect(url_for('query'))
        date = datetime.now().strftime('%Y-%m-%d')
        tenant = 'iwb'
        user_id = session.get('user_id')
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT keyword, response FROM query_templates')
        templates = c.fetchall()
        response = None
        is_auto_responded = False
        for keyword, template_response in templates:
            if keyword.lower() in message.lower():
                response = template_response
                is_auto_responded = True
                break
        if not response:
            c.execute('SELECT message, response FROM queries WHERE tenant = %s AND status = %s', (tenant, 'complete'))
            past_queries = c.fetchall()
            for pq_message, pq_response in past_queries:
                similarity = SequenceMatcher(None, message.lower(), pq_message.lower()).ratio()
                if similarity > 0.8:
                    response = pq_response
                    is_auto_responded = True
                    break
        
        status = 'complete' if response else 'pending'
        c.execute('INSERT INTO queries (name, email, message, status, response, date, tenant, user_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
                 (name, email, message, status, response, date, tenant, user_id))
        conn.commit()
        conn.close()
        flash('Query submitted. ' + ('Auto-responded.' if response else 'Pending review.'))
        return redirect(url_for('query'))
    
    conn = get_db()
    c = conn.cursor()
    queries = []
    if session.get('user_type') == 'sales':
        c.execute('SELECT * FROM queries WHERE tenant = %s', ('iwb',))
        queries = c.fetchall()
    elif session.get('user_type') == 'customer' and session.get('user_id'):
        c.execute('SELECT * FROM queries WHERE user_id = %s', (session['user_id'],))
        queries = c.fetchall()
    
    c.execute('SELECT status, COUNT(*) FROM queries WHERE tenant = %s GROUP BY status', ('iwb',))
    status_counts = c.fetchall()
    statuses = [sc[0] for sc in status_counts]
    counts = [sc[1] for sc in status_counts]
    plt.figure(figsize=(6, 6))
    plt.pie(counts, labels=statuses, autopct='%1.1f%%', colors=['#ff9999', '#66b3ff'])
    plt.title('Query Status Distribution')
    img_query = io.BytesIO()
    plt.savefig(img_query, format='png')
    img_query.seek(0)
    query_url = base64.b64encode(img_query.getvalue()).decode()
    plt.close()
    
    conn.close()
    return render_template('query.html', queries=queries, query_url=query_url)

@app.route('/respond_query/<int:query_id>', methods=['POST'])
@role_required('sales')
@mfa_required
def respond_query(query_id):
    response = request.form['response']
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE queries SET response = %s, status = %s WHERE id = %s AND tenant = %s',
             (response, 'complete', query_id, session['tenant']))
    conn.commit()
    conn.close()
    flash('Query responded.')
    return redirect(url_for('query'))

@app.route('/backup', methods=['GET', 'POST'])
@role_required('developer')
@mfa_required
def backup():
    if request.method == 'POST':
        backup_type = request.form['backup_type']
        conn = get_db()
        c = conn.cursor()
        filename = f'backup_{backup_type}_{session["tenant"]}_{datetime.now().strftime("%Y%m%d")}.csv'
        if backup_type == 'sales':
            c.execute('SELECT * FROM sales WHERE tenant = %s', (session['tenant'],))
            data = c.fetchall()
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['id', 'product_id', 'quantity', 'total', 'date', 'tenant', 'user_id'])
                writer.writerows(data)
        elif backup_type == 'queries':
            c.execute('SELECT * FROM queries WHERE tenant = %s', (session['tenant'],))
            data = c.fetchall()
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['id', 'name', 'email', 'message', 'status', 'response', 'date', 'tenant', 'user_id'])
                writer.writerows(data)
        conn.close()
        flash(f'{backup_type} backed up.')
        return send_file(filename, as_attachment=True)
    return render_template('backup.html')

# Initialize database and create sample users
if __name__ == '__main__':
    init_db()
    conn = get_db()
    c = conn.cursor()
    users = [
        ('sales1_iwb', 'password1', 'sales', 'iwb'),
        ('sales2_iwb', 'password2', 'sales', 'iwb'),
        ('sales3_iwb', 'password3', 'sales', 'iwb'),
        ('finance1_iwb', 'password4', 'finance', 'iwb'),
        ('finance2_iwb', 'password5', 'finance', 'iwb'),
        ('finance3_iwb', 'password6', 'finance', 'iwb'),
        ('dev1_iwb', 'password7', 'developer', 'iwb'),
        ('dev2_iwb', 'password8', 'developer', 'iwb'),
        ('dev3_iwb', 'password9', 'developer', 'iwb'),
        ('investor1_iwb', 'password10', 'investor', 'iwb'),
        ('finance1_iwc', 'password11', 'finance', 'iwc'),
        ('dev1_iwc', 'password12', 'developer', 'iwc'),
        ('customer1_iwb', 'password13', 'customer', 'iwb'),
    ]
    for username, password, user_type, tenant in users:
        try:
            c.execute('INSERT INTO users (username, password, user_type, tenant, mfa_code) VALUES (%s, %s, %s, %s, %s)',
                     (username, generate_password_hash(password), user_type, tenant, '123456'))
        except mysql.connector.IntegrityError:
            pass
    conn.commit()
    conn.close()
    app.run(debug=True)
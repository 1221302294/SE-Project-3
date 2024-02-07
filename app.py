from flask import Flask, render_template, request, redirect, url_for, session, request
from flask_sqlalchemy import SQLAlchemy
from flask import flash
from flask_migrate import Migrate
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash  
import qrcode
import base64
from io import BytesIO



app = Flask(__name__)
app.secret_key = 'hello'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    ic_number = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    qr_code = db.Column(db.String(255))
    
class Visitor(db.Model):
    __tablename__ = 'visitors'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False, unique=True)
    ic_number = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)
    qr_code = db.Column(db.String(255))
    


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        phone_number = request.form['phone_number']
        email = request.form['email']
        ic_number = request.form['ic_number']
        password = request.form['password']
        role = request.form['user_type']

        print(f"Received form data: {name}, {phone_number}, {email}, {ic_number}, {password}")

        
        new_user = User(name=name, phone_number=phone_number, email=email, ic_number=ic_number, password=generate_password_hash(password), role=role)

        try:
            db.session.add(new_user)
            db.session.commit()
            print("User added to the database successfully")

            # Use Flask's flash to store a success message
            flash('Account registered successfully!', 'success')

            return redirect(url_for('home', success=True))
        except Exception as e:
            db.session.rollback()
            # Handle the case where the user code is not unique
            flash('Error in signing up. Please try again.', 'error')
            return render_template('signup.html')

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id  # Store user's ID in the session
            if user.role == 'owner':
                return redirect(url_for('owner_page'))
            elif user.role == 'tenant':
                return redirect(url_for('tenant_page'))
            else:
                return redirect(url_for('visitor_page'))
        else:
            flash('Invalid email or password. Please try again.', 'error')

    return render_template('login.html')



@app.route('/view_users')
def view_users():
    users = User.query.all()
    visitors = Visitor.query.all()
    return render_template('view_users.html', users=users, visitors=visitors)

@app.route('/admin')
def admin_page():
    return render_template('admin.html')

@app.route('/owner')
def owner_page():
    if 'user_id' in session:
        user_id = session['user_id']
        owner = User.query.get(user_id)
        if owner and owner.role == 'owner':
            return render_template('owner.html', user=owner)  # Change 'owner' to 'user'
    return redirect(url_for('home'))

@app.route('/tenant')
def tenant_page():
    if 'user_id' in session:
        user_id = session['user_id']
        tenant = User.query.get(user_id)
        if tenant and tenant.role == 'tenant':
            return render_template('tenant.html', user=tenant)  # Change 'tenant' to 'user'
    return redirect(url_for('home'))

@app.route('/visitor')
def visitor_page():
    if 'user_id' in session:
        user_id = session['user_id']
        visitor = Visitor.query.get(user_id)
        if visitor:
            # Retrieve the QR code URL associated with the visitor from the database
            qr_code_url = visitor.qr_code
            
            return render_template('visitor.html', user=visitor, qr_code_url=qr_code_url)
    return redirect(url_for('home'))



@app.route('/register_visitor', methods=['POST'])
def register_visitor():
    # Retrieve form data
    name = request.form['name']
    phone_number = request.form['phone_number']
    ic_number = request.form['ic_number']
    password = generate_password_hash(request.form['password'])

    # Create a new Visitor instance
    new_visitor = Visitor(name=name, phone_number=phone_number, ic_number=ic_number, password=password)

    try:
        # Add the new visitor to the database
        db.session.add(new_visitor)
        db.session.commit()

        # Use Flask's flash to store a success message
        flash('Visitor account registered successfully!', 'success')

        # Redirect to the Tenant page or another appropriate page
        return redirect(url_for('tenant_page'))

    except Exception as e:
        # Handle errors, e.g., if the phone_number or ic_number is not unique
        db.session.rollback()

        # Use Flask's flash to store an error message
        flash('Error in registering visitor. Please try again.', 'error')

        # Redirect to the Tenant Registration page
        return redirect(url_for('tenant_registration'))

@app.route('/tenant_registration')
def tenant_registration():
    return render_template('tenant_registration.html')

@app.route('/visitor_login', methods=['GET', 'POST'])
def visitor_login():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        
        # Query the database to find the visitor by name
        visitor = Visitor.query.filter_by(name=name).first()
        
        if visitor:
            # If visitor exists, check if the password matches
            if check_password_hash(visitor.password, password):
                # Login successful
                # Redirect the visitor to the visitor page after successful login
                session['user_id'] = visitor.id  # Store visitor's ID in the session
                return redirect(url_for('visitor_page'))
            else:
                # Password does not match
                flash('Invalid name or password. Please try again.', 'error')
        else:
            # Visitor with given name does not exist
            flash('Invalid name or password. Please try again.', 'error')
    
    # Render the visitor login page
    return render_template('visitor_login.html')


@app.route('/tenant_qr_input', methods=['GET', 'POST'])
def tenant_qr_input():
    if request.method == 'POST':
        visitor_name = request.form['visitor_name']
        # Here you can perform any necessary validation or processing
        
        # Assuming you have a function to generate the QR code URL based on visitor's name
        qr_code_url = generate_qr_code_url(visitor_name)
        
        return render_template('generate_qr_code.html', qr_code=qr_code_url)
    
    return render_template('tenant_qr_input.html')

@app.route('/view_qr_code')
def view_qr_code():
    # Retrieve the visitor's QR code URL from the database
    visitor = Visitor.query.filter_by(name=session['visitor_name']).first()
    qr_code_url = visitor.qr_code_url if visitor else None
    
    # Render the view_qr_code.html template with the QR code URL
    return render_template('view_qr_code.html', qr_code_url=qr_code_url)


def generate_qr_code_url(visitor_name):
    # Logic to generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(visitor_name)
    qr.make(fit=True)

    # Create an in-memory binary stream to save the QR code image
    qr_code_stream = BytesIO()
    qr.make_image(fill_color="black", back_color="white").save(qr_code_stream, format="PNG")

    # Encode the QR code image bytes as a base64 string
    qr_code_base64 = base64.b64encode(qr_code_stream.getvalue()).decode()
    qr_code_url = f"data:image/png;base64,{qr_code_base64}"

    return qr_code_url

@app.route('/generate_qr_code', methods=['POST'])
def generate_qr_code():
    if request.method == 'POST':
        visitor_name = request.form['visitor_name']
        
        # Check if a user with the provided name exists
        user = User.query.filter_by(name=visitor_name).first()
        if user:
            # Generate the QR code URL
            qr_code_url = generate_qr_code_url(visitor_name)
            
            # Update the user's record in the database with the QR code URL
            user.qr_code = qr_code_url
            db.session.commit()
            
            # Render the view_qr_code.html template with the QR code URL
            return render_template('view_qr_code.html', qr_code_url=qr_code_url)
        else:
            # Check if a visitor with the provided name exists
            visitor = Visitor.query.filter_by(name=visitor_name).first()
            if visitor:
                # Generate the QR code URL
                qr_code_url = generate_qr_code_url(visitor_name)
                
                # Update the visitor's record in the database with the QR code URL
                visitor.qr_code = qr_code_url
                db.session.commit()
                
                # Render the view_qr_code.html template with the QR code URL
                return render_template('view_qr_code.html', qr_code_url=qr_code_url)
            else:
                # Neither user nor visitor with the provided name exists
                flash('User or visitor not found. Please enter a valid name.', 'error')
                return redirect(url_for('tenant_qr_input'))


@app.route('/view_generated_qr_code')
def view_generated_qr_code():
    # Here you need to retrieve the QR code URL for the visitor from the database
    # For demonstration purposes, I'll assume you have a function to get the QR code URL based on the visitor's name
    visitor_name = request.args.get('visitor_name')
    qr_code_url = get_qr_code_url(visitor_name)
    
    # Render the view_qr_code.html template with the QR code URL
    return render_template('view_qr_code.html', qr_code_url=qr_code_url)

def get_qr_code_url(visitor_name):
    # Query the database to find the visitor by name
    visitor = Visitor.query.filter_by(name=visitor_name).first()
    
    if visitor:
        # Assuming the visitor has a field named qr_code_url
        qr_code_url = visitor.qr_code_url
        return qr_code_url
    else:
        # Visitor with the given name does not exist
        return None

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()  # Clear the session data
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables within the application context
        
    app.run(debug=True)




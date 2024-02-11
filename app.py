from flask import Flask, render_template, request, redirect, url_for, session, request
from flask_sqlalchemy import SQLAlchemy
from flask import flash
from flask_migrate import Migrate
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash  
import qrcode
import base64
from io import BytesIO
from datetime import datetime


db = SQLAlchemy()



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

class IncidentReport(db.Model):
    __tablename__ = 'incident_reports'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', backref='incident_reports')
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  # Add timestamp field
    
class Announcement(db.Model):
    __tablename__ = 'announcements'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"Announcement('{self.title}', '{self.created_at}')"

class SOSReport(db.Model):
    __tablename__ = 'sos_reports'
    id = db.Column(db.Integer, primary_key=True)
    place = db.Column(db.String(100), nullable=False)
    level = db.Column(db.String(50), nullable=False)
    block = db.Column(db.String(50), nullable=False)
    additional_info = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

@app.route('/')
def home():
    return render_template('index.html', background_image='background.jpg')


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

@app.route('/login_board')
def login_board():
    return render_template('login_board.html')

@app.route('/login/<role>')
def role_login(role):
    return render_template('login.html', role=role)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            if user.role == 'admin':
                return redirect(url_for('admin_page'))
            elif user.role == 'owner':
                return redirect(url_for('owner_page'))
            elif user.role == 'tenant':
                return redirect(url_for('tenant_page'))
            elif user.role == 'security':  # Add this condition for the security role
                return redirect(url_for('security_page'))
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
    if 'user_id' in session:
        user_id = session['user_id']
        admin = User.query.get(user_id)
        if admin and admin.role == 'admin':
            # Fetch all users from the User table
            users = User.query.all()
            return render_template('admin.html', user=admin, users=users)  
    return redirect(url_for('home'))

@app.route('/security')
def security_page():
    if 'user_id' in session:
        user_id = session['user_id']
        security_user = User.query.get(user_id)
        if security_user and security_user.role == 'security':
            return render_template('security.html', user=security_user)
    return redirect(url_for('home'))

@app.route('/owner')
def owner_page():
    if 'user_id' in session:
        user_id = session['user_id']
        owner = User.query.get(user_id)
        if owner and owner.role == 'owner':
            return render_template('owner.html', user=owner)  
    return redirect(url_for('home'))

@app.route('/tenant')
def tenant_page():
    if 'user_id' in session:
        user_id = session['user_id']
        tenant = User.query.get(user_id)
        if tenant and tenant.role == 'tenant':
            return render_template('tenant.html', user=tenant)  
    return redirect(url_for('home'))

@app.route('/visitor')
def visitor_page():
    if 'visitor_id' in session:
        visitor_id = session['visitor_id']
        visitor = Visitor.query.get(visitor_id)
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
                session['visitor_id'] = visitor.id  # Store visitor's ID in the session
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

@app.route('/submit_incident_report', methods=['POST'])
def submit_incident_report():
    print("Inside submit_incident_report function.")  # New print statement

    if 'user_id' in session:
        print("User is logged in.")  # New print statement
        
        user_id = session['user_id']
        description = request.form['incident_description']
        user = User.query.get(user_id)
        if user:
            print("User found.")  # New print statement

            # Create a new incident report
            new_incident_report = IncidentReport(user_id=user_id, description=description)
            try:
                db.session.add(new_incident_report)
                db.session.commit()
                flash('Incident report submitted successfully!', 'success')
                print("Incident report submitted successfully.")  # New print statement
                print("Description:", description)  # New print statement

            except Exception as e:
                db.session.rollback()
                flash('Error submitting incident report. Please try again.', 'error')
                print("Error submitting incident report:", e)  # New print statement
        else:
            flash('User not found. Please login again.', 'error')
            print("User not found.")  # New print statement
    else:
        flash('You need to login to submit an incident report.', 'error')
        print("User not logged in.")  # New print statement
    
    # Redirect back to the same page
    return redirect(request.referrer)



@app.route('/view_incident_reports')
def view_incident_reports():
    # Fetch all incident reports from the database
    incident_reports = IncidentReport.query.all()
    return render_template('view_incident_reports.html', incident_reports=incident_reports)


# Define the route to resolve the report
@app.route('/resolve_report/<int:report_id>', methods=['POST'])
def resolve_report(report_id):
    # Fetch the incident report by its ID
    incident_report = IncidentReport.query.get_or_404(report_id)
    
    # Delete the incident report from the database
    db.session.delete(incident_report)
    db.session.commit()
    
    # Redirect back to the view incident reports page
    return redirect(url_for('view_incident_reports'))


@app.route('/user_management')
def user_management():
    # Retrieve all registered users from the database
    users = User.query.all()
    return render_template('user_management.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    # Fetch the user from the database based on the user_id
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Handle form submission to update user details
        user.name = request.form['name']
        user.phone_number = request.form['phone_number']
        user.email = request.form['email']
        user.ic_number = request.form['ic_number']
        user.role = request.form['role']
        
        # Commit changes to the database
        db.session.commit()
        
        # Redirect to the user management page after editing
        return redirect(url_for('user_management'))
    
    # Render the edit_user.html template with the user details
    return render_template('edit_user.html', user=user)

@app.route('/view_announcements')
def view_announcements():
    # Query the database for announcements
    announcements = Announcement.query.all()
    
    # Render the template with the announcements
    return render_template('view_announcements.html', announcements=announcements)

@app.route('/new_announcement', methods=['GET'])
def new_announcement():
    return render_template('new_announcement.html')

@app.route('/create_announcement', methods=['POST'])
def create_announcement():
    title = request.form['title']
    content = request.form['content']
    
    # Create a new Announcement instance
    new_announcement = Announcement(title=title, content=content)
    
    # Add the new announcement to the database
    db.session.add(new_announcement)
    db.session.commit()
    
    # Redirect to the view announcements page
    return redirect(url_for('view_announcements'))

@app.route('/edit_announcement/<int:announcement_id>', methods=['GET'])
def edit_announcement(announcement_id):
    announcement = Announcement.query.get_or_404(announcement_id)
    return render_template('edit_announcement.html', announcement=announcement)

@app.route('/update_announcement/<int:announcement_id>', methods=['POST'])
def update_announcement(announcement_id):
    # Retrieve the announcement from the database
    announcement = Announcement.query.get_or_404(announcement_id)
    
    # Update the announcement with the new data
    announcement.title = request.form['title']
    announcement.content = request.form['content']
    
    # Commit the changes to the database
    db.session.commit()
    
    # Redirect to the view announcements page
    return redirect(url_for('view_announcements'))


@app.route('/delete_announcement/<int:announcement_id>', methods=['POST'])
def delete_announcement(announcement_id):
    # Query the database for the announcement to delete
    announcement = Announcement.query.get_or_404(announcement_id)
    
    # Delete the announcement from the database
    db.session.delete(announcement)
    db.session.commit()
    
    # Redirect to the view announcements page
    return redirect(url_for('view_announcements'))


@app.route('/view_announcements_for_user')
def view_announcements_for_user():
    announcements = Announcement.query.all()
    return render_template('view_announcements_for_user.html', announcements=announcements)


@app.route('/verify_qr', methods=['GET', 'POST'])
def verify_qr():
    if request.method == 'POST':
        visitor_name = request.form['visitor_name']
        # Query the database to check if the visitor exists and has a QR code
        visitor = Visitor.query.filter_by(name=visitor_name).first()
        if visitor and visitor.qr_code:
            # If visitor and QR code exist, redirect to a page to display the QR code
            return render_template('verify_qr.html', visitor_name=visitor_name, qr_code_url=visitor.qr_code)
        else:
            error = 'Visitor or QR code not found.'
    else:
        error = None

    return render_template('verify_qr.html', error=error)


@app.route('/find_parking', methods=['GET'])
def find_parking():
    return render_template('find_parking.html')

@app.route('/reserve_parking', methods=['POST'])
def reserve_parking():
    parking_slot = request.form['parking_slot']
    # Here you can implement logic to reserve the parking slot (e.g., update database)
    return render_template('parking_reserved.html', parking_slot=parking_slot)

@app.route('/sos_button')
def sos_button():
    return render_template('sos_button.html')

@app.route('/sos_form')
def sos_form():
    return render_template('sos_form.html')

@app.route('/submit_sos', methods=['GET', 'POST'])
def submit_sos():
    if request.method == 'POST':
        # Get the SOS information from the form
        place = request.form['place']
        level = request.form['level']
        block = request.form['block']
        additional_info = request.form['additional_info']
        
        # Create a new SOS report instance
        new_sos_report = SOSReport(place=place, level=level, block=block, additional_info=additional_info)
        
        try:
            # Add the new SOS report to the database session
            db.session.add(new_sos_report)
            # Commit the changes to persist the SOS report in the database
            db.session.commit()
            # Redirect the user to a confirmation page or the same SOS page
            return render_template('sos_confirmation.html', place=place, level=level, block=block, additional_info=additional_info)
        except Exception as e:
            # Handle database errors
            db.session.rollback()
            flash('Error submitting SOS report. Please try again.', 'error')
    
    # Render the SOS form template for GET requests
    return render_template('sos_form.html')

@app.route('/view_sos_reports')
def view_sos_reports():
    # Query the database for all SOS reports
    sos_reports = SOSReport.query.all()
    return render_template('view_sos_reports.html', sos_reports=sos_reports)

@app.route('/resolve_sos/<int:sos_id>', methods=['POST'])
def resolve_sos(sos_id):
    # Find the SOS report by its ID
    sos_report = SOSReport.query.get_or_404(sos_id)
    if sos_report:
        # Delete the SOS report from the database
        db.session.delete(sos_report)
        db.session.commit()
        flash('SOS Report resolved successfully.', 'success')
    else:
        flash('SOS Report not found.', 'error')
    return redirect(url_for('view_sos_reports'))



if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables within the application context
        
    app.run(debug=True)




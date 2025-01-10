from flask import Flask, jsonify, request
import random
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime  # Import timedelta and datetime together
import psycopg2
import requests


try:
    import psycopg2
except ImportError:
    psycopg2 = None
    print("psycopg2 module is not installed. Install it by running 'pip install psycopg2-binary'.")

try:
    from config import DATABASE_CONFIG
except ImportError:
    DATABASE_CONFIG = None
    print("DATABASE_CONFIG could not be imported. Ensure 'config.py' exists and defines DATABASE_CONFIG.")

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

# JWT configuration
app.config['JWT_SECRET_KEY'] = 'your-strong-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)


jwt = JWTManager(app)

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'dajafranko@gmail.com'
app.config['MAIL_PASSWORD'] = 'qcwn chhd xpep efdh'

mail = Mail(app)

# Database connection function
def get_db_connection():
    if not psycopg2:
        raise ImportError("psycopg2 is not available. Please ensure it is installed.")
    if not DATABASE_CONFIG:
        raise ImportError("DATABASE_CONFIG is not available. Please ensure it is correctly defined in 'config.py'.")
    conn = psycopg2.connect(**DATABASE_CONFIG)
    return conn

def send_confirmation_email(email, confirmation_code):
    try:
        msg = Message(
            'Your Registration Confirmation Code',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f"Your confirmation code is: {confirmation_code}"
        mail.send(msg)
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

@app.route('/test-email', methods=['GET'])
def test_email():
    try:
        test_email = "recipient@example.com"
        send_confirmation_email(test_email, "123456")
        return jsonify({'message': 'Test email sent successfully!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/')
def index():
    return jsonify({'message': 'Welcome to the MG Project API!'})

@app.route('/db_test')
def db_test():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT version();')
        db_version = cur.fetchone()
        cur.close()
        conn.close()
        return jsonify({'database_version': db_version[0]})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    try:
        password = data.get('password')
        if not password:
            return jsonify({'error': 'Password is required'}), 400

        hashed_password = generate_password_hash(password)
        confirmation_code = str(random.randint(100000, 999999))

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO users (name, username, email, password_hash, confirmation_code, is_verified)
            VALUES (%s, %s, %s, %s, %s, FALSE) RETURNING id
            """,
            (data['name'], data['username'], data['email'], hashed_password, confirmation_code)
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        send_confirmation_email(data['email'], confirmation_code)

        return jsonify({'id': user_id, 'message': 'User registered successfully! Please check your email for the confirmation code.'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/confirm', methods=['POST'])
def confirm_user():
    data = request.json
    email = data.get('email')
    code = data.get('confirmation_code')
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM users WHERE email = %s AND confirmation_code = %s AND is_verified = FALSE",
            (email, code)
        )
        user = cur.fetchone()

        if not user:
            return jsonify({'error': 'Invalid email or confirmation code.'}), 400

        cur.execute(
            "UPDATE users SET is_verified = TRUE, confirmation_code = NULL WHERE id = %s",
            (user[0],)
        )
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'message': 'User verified successfully!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT id, password_hash FROM users WHERE username = %s', (username,))
        user = cur.fetchone()

        if not user or not check_password_hash(user[1], password):
            return jsonify({'error': 'Invalid username or password'}), 401

        access_token = create_access_token(identity=str(user[0]))
        cur.close()
        conn.close()

        return jsonify({'access_token': access_token, 'user_id': user[0]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/report_types', methods=['GET'])
def get_report_types():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT report_type_id, report_type_name FROM report_type")
        report_types = cur.fetchall()

        report_types_list = [
            {"report_type_id": rt[0], "report_type_name": rt[1]} for rt in report_types
        ]

        cur.close()
        conn.close()

        return jsonify(report_types_list), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch report types", "message": str(e)}), 500

@app.route('/users/<int:user_id>/gadgets', methods=['GET'])
@jwt_required()
def get_user_gadgets(user_id):
    is_deleted = request.args.get('is_deleted', 'false').lower() == 'true'
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        query = '''
            SELECT g.id, g.gadget_name, g.serial_number, g.note, rt.report_type_name, g.is_deleted, g.created_at
            FROM gadgets g
            JOIN report_type rt ON g.report_type_id = rt.report_type_id
            WHERE g.owner_id = %s AND g.is_deleted = %s
            ORDER BY g.created_at DESC
        '''
        cur.execute(query, (user_id, is_deleted))
        gadgets = cur.fetchall()

        result = [
            {
                'id': gadget[0],
                'gadget_name': gadget[1],
                'serial_number': gadget[2],
                'note': gadget[3],
                'report_type': gadget[4],
                'is_deleted': gadget[5],
                'created_at': gadget[6].isoformat()
            }
            for gadget in gadgets
        ]

        cur.close()
        conn.close()

        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/gadgets', methods=['POST'])
def add_gadget():
    data = request.json
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO gadgets (owner_id, gadget_name, serial_number, note, report_type_id)
            VALUES (%s, %s, %s, %s, %s) RETURNING id
            """,
            (data['owner_id'], data['gadget_name'], data['serial_number'], data['note'], data['report_type_id'])
        )
        gadget_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'id': gadget_id, 'message': 'Gadget registered successfully!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/gadgets/<int:gadget_id>/update', methods=['PUT'])
def update_gadget(gadget_id):
    data = request.json
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            '''
            UPDATE gadgets
            SET gadget_name = %s, serial_number = %s, report_type_id = %s, note = %s, last_updated_at = CURRENT_TIMESTAMP
            WHERE id = %s AND is_deleted = FALSE
            RETURNING id, gadget_name, serial_number, report_type_id, note
            ''',
            (data['gadget_name'], data['serial_number'], data['report_type_id'], data['note'], gadget_id)
        )
        updated_gadget = cur.fetchone()

        conn.commit()
        cur.close()
        conn.close()

        if not updated_gadget:
            return jsonify({'error': 'Gadget not found or already deleted'}), 404

        return jsonify({
            'id': updated_gadget[0],
            'gadget_name': updated_gadget[1],
            'serial_number': updated_gadget[2],
            'report_type_id': updated_gadget[3],
            'note': updated_gadget[4],
            'message': 'Gadget updated successfully!'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/gadgets/<int:gadget_id>', methods=['PUT'])
@jwt_required()
def soft_delete_gadget(gadget_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Soft delete the gadget
        cur.execute(
            "UPDATE gadgets SET is_deleted = TRUE WHERE id = %s RETURNING id",
            (gadget_id,)
        )
        deleted_gadget = cur.fetchone()

        conn.commit()
        cur.close()
        conn.close()

        if not deleted_gadget:
            return jsonify({'error': 'Gadget not found'}), 404

        return jsonify({'message': 'Gadget soft deleted successfully!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/gadgets/<int:gadget_id>/recover', methods=['PUT'])
def recover_gadget(gadget_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            '''
            UPDATE gadgets
            SET is_deleted = FALSE
            WHERE id = %s
            RETURNING id, gadget_name, serial_number, note, is_deleted
            ''',
            (gadget_id,)
        )
        recovered_gadget = cur.fetchone()

        if not recovered_gadget:
            return jsonify({'error': 'Gadget not found or already active'}), 404

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            'id': recovered_gadget[0],
            'gadget_name': recovered_gadget[1],
            'serial_number': recovered_gadget[2],
            'note': recovered_gadget[3],
            'is_deleted': recovered_gadget[4],
            'message': 'Gadget recovered successfully!'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT name, username, email FROM users WHERE id = %s",
            (user_id,)
        )
        user = cur.fetchone()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        cur.close()
        conn.close()

        return jsonify({
            'name': user[0],
            'username': user[1],
            'email': user[2],
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    


@app.route('/users/<int:user_id>/update', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    try:
        data = request.json
        name = data.get('name')
        username = data.get('username')
        email = data.get('email')

        if not all([name, username, email]):
            return jsonify({'error': 'All fields (name, username, email) are required'}), 400

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            '''
            UPDATE users
            SET name = %s, username = %s, email = %s
            WHERE id = %s
            RETURNING name, username, email
            ''',
            (name, username, email, user_id)
        )
        updated_user = cur.fetchone()

        if not updated_user:
            return jsonify({'error': 'User not found'}), 404

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            'name': updated_user[0],
            'username': updated_user[1],
            'email': updated_user[2],
            'message': 'User details updated successfully!'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/users/<int:user_id>/change-password', methods=['PUT'])
@jwt_required()
def change_password(user_id):
    try:
        # Get the current user ID from the JWT
        current_user_id = get_jwt_identity()

        # Ensure the user ID from the URL matches the logged-in user
        if str(current_user_id) != str(user_id):
            return jsonify({'error': 'Unauthorized access'}), 403

        # Get the request data
        data = request.json
        current_password = data.get('currentPassword')
        new_password = data.get('newPassword')

        # Validate input
        if not current_password or not new_password:
            return jsonify({'error': 'Both current and new passwords are required'}), 400

        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch the user's current password hash
        cur.execute('SELECT password_hash FROM users WHERE id = %s', (user_id,))
        user = cur.fetchone()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        password_hash = user[0]

        # Verify the current password
        if not check_password_hash(password_hash, current_password):
            return jsonify({'error': 'Current password is incorrect'}), 400

        # Hash the new password
        new_password_hash = generate_password_hash(new_password)

        # Update the password in the database
        cur.execute(
            'UPDATE users SET password_hash = %s WHERE id = %s',
            (new_password_hash, user_id)
        )
        conn.commit()

        cur.close()
        conn.close()

        return jsonify({'message': 'Password changed successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/gadgets/search', methods=['POST'])
def search_gadget():
    """
    Handle a search for a gadget based on its serial number.
    Log the search, collect details, and send an email to the gadget owner.
    """
    # Parse request data
    data = request.json
    serial_number = data.get('serial_number')
    latitude = data.get('latitude')
    longitude = data.get('longitude')

    # Validate input
    if not serial_number:
        return jsonify({"error": "Serial number is required"}), 400

    # Log the search and get the Google Maps link
    google_maps_link = log_search(serial_number, latitude, longitude)

    # Collect search details
    search_details = {
        "serial_number": serial_number,
        "google_maps_link": google_maps_link,
        "ip_address": get_client_ip(),
        "search_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "country": "Albania",  # Replace with actual country from geolocation
        "region_name": "Tirana",  # Replace with actual region from geolocation
        "city": "Tirana",  # Replace with actual city from geolocation
        "isp": "ISP Placeholder",  # Replace with actual ISP from geolocation
    }

    # Send email to the gadget owner
    send_search_email(serial_number, search_details)

    # Query the gadget details from the database
    result = search_database_for_gadget(serial_number)

    # Return the result or error message
    if result:
        result['google_maps_link'] = google_maps_link  # Include the link in the response
        return jsonify(result)
    else:
        return jsonify({"error": "Gadget not found"}), 404





    


@app.route('/search', methods=['POST'])
def search_serial():
    data = request.json
    serial_number = data.get('serial_number')
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    user_id = data.get('user_id')  # Include if user is logged in

    if not serial_number:
        return jsonify({"error": "Serial number is required"}), 400

    # Log the search
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO search_logs (serial_number, user_id, latitude, longitude, search_time)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (serial_number, user_id, latitude, longitude, datetime.now())
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Process the serial number search logic (example response)
    return jsonify({"message": "Search logged successfully", "serial_number": serial_number})    



@app.route('/search_logs/<serial_number>', methods=['GET'])
def get_search_logs(serial_number):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT latitude, longitude, search_time
        FROM search_logs
        WHERE serial_number = %s
        ORDER BY search_time DESC
        """,
        (serial_number,)
    )
    logs = cursor.fetchall()
    cursor.close()
    conn.close()

    # Format logs as a list of dictionaries
    formatted_logs = [
        {"latitude": log[0], "longitude": log[1], "search_time": log[2]}
        for log in logs
    ]

    return jsonify(formatted_logs)


def log_search(serial_number, latitude, longitude):
    ip_address = get_client_ip()  # Capture the IP address
    google_maps_link = f"https://www.google.com/maps?q={latitude},{longitude}"  # Generate the Google Maps link

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO search_logs (serial_number, latitude, longitude, google_maps_link, ip_address, search_time)
        VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        """,
        (serial_number, latitude, longitude, google_maps_link, ip_address)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return google_maps_link





def search_database_for_gadget(serial_number):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Query the gadget based on the serial number
    cursor.execute(
        """
        SELECT serial_number, gadget_name, note, report_type_id, google_maps_link
        FROM gadgets
        WHERE serial_number = %s
        """,
        (serial_number,)
    )
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if result:
        return {
            "serial_number": result[0],
            "gadget_name": result[1],
            "note": result[2],
            "status": map_report_type(result[3]),  # Use the mapping function
            "google_maps_link": result[4],  # Return the Google Maps link
        }
    else:
        return None


def map_report_type(report_type_id):
    report_types = {
        1: "Lost",
        2: "Stolen",
        3: "Found",
        4: "Recovered",
    }
    return report_types.get(report_type_id, "Unknown")


def update_gadget_location(serial_number, latitude, longitude):
    google_maps_link = f"https://www.google.com/maps?q={latitude},{longitude}"  # Generate the link

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE gadgets
        SET google_maps_link = %s
        WHERE serial_number = %s
        """,
        (google_maps_link, serial_number)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return google_maps_link


def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        # If the app is behind a reverse proxy
        ip = request.headers['X-Forwarded-For'].split(',')[0]
    else:
        # Direct connection
        ip = request.remote_addr
    return ip




def get_ip_location(ip_address):
    response = requests.get(f"http://ip-api.com/json/{ip_address}")
    if response.status_code == 200:
        return response.json()
    return None



import requests

def get_geolocation(ip_address):
    """Fetch geolocation data for the given IP address or use default for localhost."""
    if ip_address == "127.0.0.1":
        # Use default values for local testing
        return {
            "country": "Your Country",
            "regionName": "Your Region",
            "city": "Your City",
            "isp": "Localhost",
            "org": "Localhost",
        }

    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error fetching geolocation data: {e}")
        return None


def log_search(serial_number, latitude, longitude):
    ip_address = get_client_ip()  # Capture the IP address
    geolocation_data = get_geolocation(ip_address)  # Get geolocation details

    # Default values if geolocation data is unavailable
    country = geolocation_data.get("country") if geolocation_data else None
    region_name = geolocation_data.get("regionName") if geolocation_data else None
    city = geolocation_data.get("city") if geolocation_data else None
    isp = geolocation_data.get("isp") if geolocation_data else None
    organization = geolocation_data.get("org") if geolocation_data else None

    google_maps_link = f"https://www.google.com/maps?q={latitude},{longitude}"  # Generate the Google Maps link

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO search_logs (serial_number, latitude, longitude, google_maps_link, ip_address, country, region_name, city, isp, organization, search_time)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        """,
        (serial_number, latitude, longitude, google_maps_link, ip_address, country, region_name, city, isp, organization)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return google_maps_link





def send_search_email(serial_number, search_details):
    """
    Fetch the email of the user (owner) and gadget_name associated with the gadget
    and send an email with the search details.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Updated query to fetch email and gadget_name
    cursor.execute(
        """
        SELECT users.email, gadgets.gadget_name
        FROM users
        INNER JOIN gadgets ON users.id = gadgets.owner_id
        WHERE gadgets.serial_number = %s
        """,
        (serial_number,)
    )
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if not result:
        print(f"No user or gadget found for serial number: {serial_number}")
        return

    user_email, gadget_name = result  # Fetch email and gadget_name

    # Prepare the email content
    email_subject = f"Pajisja juaj eshte kerkuar nga dikush, emri i pajisjes: {gadget_name}"
    email_body = f"""
    I dashur perdorues,
    Pajisja juaj eshte kerkuar. Keto jane te dhenat:

    -> Emri i pajisjes: {gadget_name}
    -> Numri serial: {search_details['serial_number']}
    -> Vendndodhja ku eshte kerkuar: {search_details['google_maps_link']}
    -> Adresa e IP se pajisjes nga ku eshte kerkuar:
    -> {search_details['ip_address']}
    -> Koha kur eshte kerkuar: {search_details['search_time']}
    -> Shteti: {search_details['country']}
    -> Zona: {search_details['region_name']}
    -> Qyteti: {search_details['city']}
    -> ISP: {search_details['isp']}

    Ju bejme me dije qe nese personi ka perdorur VPN ose mjete te tjera per te fshehur lokacionin, ose e ka fikur lokacionin,
    te dhenat mund te mos jene te verteta. Kontaktoni me autoritetet perkatese

    Gjithe te mirat,
    Franko Daja
    """

    # Send the email
    msg = Message(
        subject=email_subject,
        sender='your_email@gmail.com',  # Replace with your email
        recipients=[user_email],
        body=email_body
    )

    try:
        mail.send(msg)
        print(f"Email sent successfully to {user_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")











if __name__ == '__main__':
    print("Registered Routes:")
    for rule in app.url_map.iter_rules():
        print(rule)

    app.run(debug=True)

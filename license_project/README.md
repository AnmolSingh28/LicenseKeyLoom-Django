KeyLoom: A Modern Django-Based Software Licensing System
A powerful and secure software licensing solution built on the Django framework. It provides a robust backend for generating, managing, and validating license keys for software products. This system is designed to combat piracy and unauthorized use by binding license keys to specific hardware and controlling license validity.

->KEY FEATURES
Secure License Generation: Programmatically generates unique, cryptographically random license keys.

1.User Registration & Roles:
The first user to register automatically gets admin and staff privileges, allowing for easy setup. Subsequent registrations are for standard users.

2.API Endpoints: 
The core functionality is exposed via a dedicated REST API, allowing for easy integration with any client application to validate and renew licenses.

3.License Expiration & Renewal: 
All licenses have an expiration date. Users can request renewal via an API, and administrators can easily extend license validity from the dashboard.

4.Hardware Binding: 
A critical anti-piracy feature that ties a license key to a specific device's unique hardware ID. This prevents the same key from being used on multiple computers.

5.Admin Dashboard: 
A staff-only web interface for full control, including creating new licenses, viewing all existing licenses, and deleting them.

->SECURITY AND ENCRYPTION
The project uses a multi-layered security approach to protect sensitive license keys and user data. The main security mechanisms are:

1.Symmetric Encryption (Fernet): 
License keys are never stored in plain text. Instead, they are encrypted using Fernet, a symmetric encryption scheme that ensures only the intended key holder can decrypt it. The cryptography library is used for this process.

2.Password-Based Key Derivation (PBKDF2HMAC): 
A secure password hashing and key derivation function is used. When a user sets a password to view their key, the system uses a salt and 100,000 iterations to derive a strong encryption key. This makes brute-force attacks on the password virtually impossible.

3.Password Hashing: 
Before any encryption, the user's password for viewing the key is securely hashed using hashlib.pbkdf2_hmac with a unique salt. This ensures that even the password itself is never stored in a readable format.

4.Email Integration (Brevo): 
The system securely handles license requests from users and sends automated emails to the configured admin address via the Brevo (formerly Sendinblue) API, ensuring no sensitive information is exposed.

->INSTALLATION AND SETUP
Follow these simple steps to get a local copy of the project running:

1.Clone the Repository:

git clone [https://github.com/AnmolSingh28/KeyLoom-Django.git](https://github.com/AnmolSingh28/KeyLoom-Django.git)
cd KeyLoom-Django

2.Set Up Virtual Environment:

python -m venv venv
.\venv\Scripts\activate  # Windows
source venv/bin/activate # macOS/Linux

3.Install Dependencies:

pip install -r requirements.txt

4.Configure Environment Variables:
Create a .env file in the root project directory with the following variables:

SECRET_KEY='your_strong_django_secret_key'
BREVO_API_KEY='your_brevo_api_key'
DEFAULT_FROM_EMAIL='your_sender_email@example.com'

5.Run Migrations:

python manage.py migrate

6.Create an Admin User:

python manage.py createsuperuser

(The first user you create will automatically gain admin privileges.)

7.Run the Server:

python manage.py runserver

->USAGE
1.Deployment:
The live version of this tool is deployed on Render and can be accessed at: https://django-license-tool.onrender.com

2.For Admins:
Access http://localhost:8000/admin/ to manage settings and users.The main dashboard is at http://localhost:8000/licenses/create/ to generate new keys.

3.For Developers:
Integrate a client application with API endpoints to validate keys and manage licenses programmatically.

->CONTRIBUTION
All the contributions are welcome! If there is a feature related issue/feature request or a bug, please open an issue or submit a pull request.

->LICENSE
This project is licensed under the MIT License.

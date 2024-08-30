import re
import socket
from urllib.parse import urlparse
from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.model_selection import cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
from flask import Flask, render_template, request, jsonify, session, redirect
from datetime import datetime
import logging
import ssl
from sklearn.feature_extraction.text import CountVectorizer
from bleach import clean  # For input sanitization
from werkzeug.security import generate_password_hash, check_password_hash
import os
import requests
import dns.resolver
import whois
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
import mysql.connector
from tldextract import extract  # Importing tldextract to extract TLD

# Create a MySQL connection URI
mysql_uri = 'mysql+mysqlconnector://root:mysqlpassword@localhost/Phishing'

# Create SQLAlchemy engine
engine = create_engine(mysql_uri, echo=True)
Base = declarative_base()


class PhishingURL(Base):
    __tablename__ = 'phishing_urls'
    id = Column(Integer, primary_key=True)
    url = Column(String(255))
    timestamp = Column(DateTime, default=datetime.now)
    result = Column(String(255))


# Create tables in the database
Base.metadata.create_all(engine)

# Create session factory
Session = sessionmaker(bind=engine)

# Create a scoped session to manage sessions across requests
db_session = scoped_session(Session)


# Function to store URL in the database
def store_url(url, result):
    url_entry = PhishingURL(url=url, result=result)
    db_session.add(url_entry)
    db_session.commit()


# Loading and processing data for model training
def load_data_train_model():
    # Loading the data
    data0 = pd.read_csv(r"D:\python AC\Phishing Website Detection\DataFiles\5.urldata.csv")

    # Assigning a default value to data
    data = None

    # Dropping the 'Domain' column if it exists
    if 'Domain' in data0.columns:
        data = data0.drop(['Domain'], axis=1).copy()
    else:
        logging.warning("The 'Domain' column does not exist in the DataFrame.")

    # Check if data is still None after the conditional block
    if data is None:
        raise ValueError("Failed to load data. 'Domain' column is missing.")

    # Separating & assigning features and target columns to X & y
    y = data['Label']
    X = data.drop('Label', axis=1)

    # Splitting the dataset into train and test sets: 80-20 split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=12)

    # Random Forest model
    forest = RandomForestClassifier(max_depth=5)
    forest.fit(X_train, y_train)

    # Computing the accuracy of the model performance
    y_test_forest = forest.predict(X_test)
    y_train_forest = forest.predict(X_train)
    acc_train_forest = accuracy_score(y_train, y_train_forest)
    acc_test_forest = accuracy_score(y_test, y_test_forest)
    print("Random forest: Accuracy on training Data: {:.3f}".format(acc_train_forest))
    print("Random forest: Accuracy on test Data: {:.3f}".format(acc_test_forest))

    # Cross-validation
    cv_scores = cross_val_score(forest, X_train, y_train, cv=5)
    print("Cross-validation scores:", cv_scores)
    print("Mean CV accuracy:", np.mean(cv_scores))

    # Hyperparameter tuning using GridSearchCV
    param_grid = {
        'n_estimators': [50, 100, 150],
        'max_depth': [None, 5, 10]
    }

    grid = GridSearchCV(RandomForestClassifier(), param_grid, cv=3)
    grid.fit(X_train, y_train)

    print("Best parameters:", grid.best_params_)
    best_model = grid.best_estimator_

    # Define the path to save the model
    model_file_path = 'D:\python AC\Phishing Website Detection\random_forest_model.pkl'

    # Model Persistence
    joblib.dump(best_model, 'random_forest_model.pkl')
    return best_model


# Preprocessing URL for prediction
def preprocess_url(url):
    # Assuming 'Domain' is a categorical feature in your training data
    vectorizer = CountVectorizer()
    # Sanitize user input to prevent XSS attacks
    url_sanitized = clean(url, strip=True)
    X_train_vectorized = vectorizer.fit_transform([url_sanitized])
    return X_train_vectorized


# Predicting phishing or legitimate URL
def predict_phishing(url, model):
    loaded_model = joblib.load(model)
    url_vectorized = preprocess_url(url)
    prediction = loaded_model.predict(url_vectorized)[0]
    result = "Phishing" if prediction == 1 else "Legitimate"
    return result


# Function to extract features from URLs
def extract_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    have_ip = any(char.isdigit() for char in domain)
    have_at = "@" in domain
    url_length = len(url)
    url_depth = url.count("/")
    redirection = "://" in url
    https_domain = domain.startswith("https://")
    tiny_url = len(url) < 25
    prefix_suffix = "-" in domain or "_" in domain

    # DNS_Record: Check if the domain has DNS records
    try:
        dns_record = bool(dns.resolver.resolve(domain, 'A'))
    except:
        dns_record = False

    # Web_Traffic: Scrape web traffic information or use Alexa Rank API
    try:
        response = requests.get("https://www.alexa.com/siteinfo/" + domain)
        web_traffic = response.json()["trafficData"]["rank"]["global"]
    except:
        web_traffic = 0

    # Domain_Age: Query WHOIS database to get domain creation date
    try:
        domain_info = whois.whois(domain)
        domain_age = (datetime.now() - domain_info.creation_date[0]).days
    except:
        domain_age = 0

    # Domain_End: Extract top-level domain (TLD)
    domain_end = extract(domain).suffix

    # Placeholder for features requiring complex analysis of webpage content
    i_frame = False
    mouse_over = False

    label = ""  # Placeholder for label

    return {
        "Domain": domain,
        "Have_IP": have_ip,
        "Have_At": have_at,
        "URL_Length": url_length,
        "URL_Depth": url_depth,
        "Redirection": redirection,
        "https_Domain": https_domain,
        "TinyURL": tiny_url,
        "Prefix/Suffix": prefix_suffix,
        "DNS_Record": dns_record,
        "Web_Traffic": web_traffic,
        "Domain_Age": domain_age,
        "Domain_End": domain_end,
        "iFrame": i_frame,
        "Mouse_Over": mouse_over,
        "Label": label
    }


# Function to check Safe Browsing Transparency Report
def check_transparency_report(url):
    api_key = "AIzaSyCr8zBWH1m7KD2DaQAIcxSQvnIEgTcZSao"  # Replace with your Google API Key
    api_url = f"https://safebrowsing.googleapis.com/v4/transparencyreport/unsafe_sites?key={api_key}"
    payload = {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"],
               "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}
    headers = {"Content-Type": "application/json"}
    response = requests.post(api_url, json=payload, headers=headers)
    if response.status_code == 200:
        report = response.json()
        if "matches" in report:
            return True  # Phishing: URL found in the transparency report
    return False  # Legitimate URL or not found in the transparency report


# Creating Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a secure random secret key


# User authentication and password hashing
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def to_dict(self):
        return {
            'username': self.username,
            # It's not recommended to include the password in the dictionary for security reasons
            # 'password': self.password,
        }


# Register route to create a new user
@app.route('/registration', methods=['GET'])
def registration():
    return render_template('registration.html')


@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    new_user = User(username=username, password=password)
    session['current_user'] = new_user.to_dict()  # Store user data in session (you might use a database)
    return redirect('/login')


# Login route for user authentication
@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_user():
    username = request.form['username']
    password = request.form['password']
    current_user = session.get('current_user')  # Retrieve current_user from the session

    if current_user and current_user['username'] == username:  # Check if the username exists in session
        user = User(username=username, password=password)
        if user.check_password(password):  # Check password against hashed password
            session['logged_in'] = True  # Create session upon successful authentication
            return render_template('index.html')

    return 'Invalid username or password!'


# Logout route to end the user session
@app.route('/logout')
def logout():
    session.pop('logged_in', None)  # Clear the session when the user logs out
    return 'Logged out successfully!'


# Function to check SSL certificate
def check_ssl_certificate(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert['subjectAltName']:
                    return True  # SSL certificate exists
                else:
                    return False  # No SSL certificate
    except Exception as e:
        print(f"Error checking SSL certificate: {e}")
        return False


# Function to retrieve WHOIS information
def get_whois_info(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        print(f"Error retrieving WHOIS information: {e}")
        return None


# Function to analyze page content
def analyze_page_content(url):
    # Add your page content analysis logic here
    return None  # Placeholder for page content analysis


# Index route for phishing website detection
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'logged_in' in session:  # Check if user is logged in
            url = request.json['url']
            features = extract_features(url)
            features_df = pd.DataFrame([features])
            prediction = predict_phishing(url, 'random_forest_model.pkl')
            store_url(url, prediction)  # Store URL in the database

            # Check SSL certificate
            ssl_result = check_ssl_certificate(url)

            # Retrieve WHOIS information
            whois_info = get_whois_info(url)

            # Analyze page content
            page_content_analysis = analyze_page_content(url)

            # Check Safe Browsing Transparency Report
            transparency_report_result = check_transparency_report(url)
            if transparency_report_result:
                prediction = "Phishing (Safe Browsing)"

            results = pd.DataFrame({'ML Model': ['Random Forest'], 'Prediction': [prediction]})
            current_year = datetime.now().year
            return jsonify({
                'results': results.to_dict(),
                'current_year': current_year,
                'SSL_Result': ssl_result,
                'WHOIS_Info': whois_info,
                'Page_Content_Analysis': page_content_analysis
            })
        else:
            return 'Please login first!'
    return render_template('index.html')


@app.route('/favicon.ico')
def favicon():
    return '', 404


@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()  # Remove the session at the end of the request or when an exception occurs


if __name__ == '__main__':
    model = load_data_train_model()  # This should be executed only when you want to train the model
    app.run(debug=False)

# Step 1: Environment Setup and Library Imports
# Phishing URL Detection Model - Google Colab Setup
# Note: We'll use built-in urllib instead of tldextract for better compatibility

# Import essential libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

# URL processing libraries
import urllib.parse
import re
from urllib.parse import urlparse
import requests
from datetime import datetime
import socket

# Machine Learning libraries
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

# Model persistence
import joblib
import pickle

print("✅ All libraries imported successfully!")
print("📊 Ready to start building the phishing URL detection model")
print("🔍 This model will analyze URL features to detect phishing attempts")
print("\n" + "="*50)
print("PHISHING URL DETECTION MODEL - STEP 1 COMPLETE")
print("="*50)

# Step 2: Dataset Creation and Feature Extraction Functions
# Phishing URL Detection Model - Feature Engineering

def extract_url_features(url):
    """
    Extract comprehensive features from a URL for phishing detection
    """
    features = {}
    
    try:
        # Parse the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path
        query = parsed_url.query
        
        # 1. URL Length Features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        
        # 2. Character-based Features
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_questionmarks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_at_signs'] = url.count('@')
        features['num_and_signs'] = url.count('&')
        features['num_percent_signs'] = url.count('%')
        
        # 3. Suspicious Pattern Features
        features['has_ip_address'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        features['has_suspicious_tld'] = 1 if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf']) else 0
        features['has_www'] = 1 if 'www.' in domain else 0
        features['has_https'] = 1 if url.startswith('https://') else 0
        
        # 4. Domain Analysis
        features['subdomain_count'] = domain.count('.') - 1 if domain.count('.') > 1 else 0
        features['domain_has_numbers'] = 1 if re.search(r'\d', domain) else 0
        
        # 5. Suspicious Keywords
        suspicious_keywords = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm']
        features['suspicious_keywords_count'] = sum(1 for keyword in suspicious_keywords if keyword in url.lower())
        
        # 6. URL Structure Features
        features['has_shortening_service'] = 1 if any(service in domain for service in ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly']) else 0
        features['abnormal_url'] = 1 if re.search(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', url) else 0
        
        # 7. Brand impersonation indicators
        famous_brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'instagram', 'twitter', 'linkedin']
        features['brand_impersonation'] = 1 if any(brand in domain for brand in famous_brands) and not any(domain.endswith(f'.{brand}.com') for brand in famous_brands) else 0
        
        # 8. Additional suspicious patterns
        features['has_multiple_hyphens'] = 1 if url.count('-') > 3 else 0
        features['has_suspicious_port'] = 1 if ':' in parsed_url.netloc and not parsed_url.netloc.endswith(':80') and not parsed_url.netloc.endswith(':443') else 0
        features['url_entropy'] = calculate_entropy(url)
        
    except Exception as e:
        print(f"Error processing URL {url}: {str(e)}")
        # Return default features if parsing fails
        features = {feature: 0 for feature in ['url_length', 'domain_length', 'path_length', 'num_dots', 'num_hyphens', 
                                               'num_underscores', 'num_slashes', 'num_questionmarks', 'num_equal_signs',
                                               'num_at_signs', 'num_and_signs', 'num_percent_signs', 'has_ip_address',
                                               'has_suspicious_tld', 'has_www', 'has_https', 'subdomain_count',
                                               'domain_has_numbers', 'suspicious_keywords_count', 'has_shortening_service',
                                               'abnormal_url', 'brand_impersonation', 'has_multiple_hyphens',
                                               'has_suspicious_port', 'url_entropy']}
    
    return features

def calculate_entropy(text):
    """Calculate Shannon entropy of text"""
    prob = [float(text.count(c))/len(text) for c in dict.fromkeys(list(text))]
    entropy = sum([-p * np.log2(p) for p in prob])
    return entropy

# Sample dataset creation
def create_sample_dataset():
    """Create a sample dataset with legitimate and phishing URLs"""
    
    # Legitimate URLs
    legitimate_urls = [
        'https://www.google.com',
        'https://www.facebook.com/login',
        'https://github.com/user/repo',
        'https://stackoverflow.com/questions',
        'https://www.amazon.com/products',
        'https://docs.python.org/3/',
        'https://www.youtube.com/watch',
        'https://www.linkedin.com/in/profile',
        'https://www.wikipedia.org/wiki/article',
        'https://www.reddit.com/r/programming',
        'https://www.paypal.com/signin',
        'https://www.microsoft.com/office',
        'https://www.apple.com/iphone',
        'https://www.twitter.com/user',
        'https://www.instagram.com/profile',
        'https://www.netflix.com/browse',
        'https://www.spotify.com/premium',
        'https://www.dropbox.com/files',
        'https://www.medium.com/article',
        'https://www.cnn.com/news'
    ]
    
    # Phishing URLs (simulated examples)
    phishing_urls = [
        'http://paypal-security-check.tk/signin',
        'https://amazon-customer-service.ml/account',
        'http://192.168.1.1/facebook-login',
        'https://secure-banking-login.cf/verify',
        'http://microsoft-office365-signin.ga/login',
        'https://apple-id-verification.tk/confirm',
        'http://google-account-recovery.ml/reset',
        'https://instagram-security-alert.cf/verify',
        'http://linkedin-premium-offer.ga/upgrade',
        'https://twitter-account-suspended.tk/appeal',
        'http://netflix-payment-failed.ml/update',
        'https://spotify-premium-expired.cf/renew',
        'http://dropbox-storage-full.ga/upgrade',
        'https://amazon-prime-renewal.tk/payment',
        'http://paypal-limit-exceeded.ml/verify',
        'https://facebook-security-warning.cf/check',
        'http://microsoft-security-alert.ga/scan',
        'https://apple-icloud-suspended.tk/restore',
        'http://google-drive-quota-exceeded.ml/upgrade',
        'https://instagram-copyright-violation.cf/dispute'
    ]
    
    # Create labels
    legitimate_labels = [0] * len(legitimate_urls)  # 0 for legitimate
    phishing_labels = [1] * len(phishing_urls)     # 1 for phishing
    
    # Combine datasets
    all_urls = legitimate_urls + phishing_urls
    all_labels = legitimate_labels + phishing_labels
    
    return all_urls, all_labels

# Create the dataset
print("🔄 Creating sample dataset...")
urls, labels = create_sample_dataset()

print(f"✅ Dataset created successfully!")
print(f"📊 Total URLs: {len(urls)}")
print(f"📊 Legitimate URLs: {labels.count(0)}")
print(f"📊 Phishing URLs: {labels.count(1)}")

# Extract features for all URLs
print("\n🔄 Extracting features from URLs...")
feature_list = []
for url in urls:
    features = extract_url_features(url)
    feature_list.append(features)

# Create DataFrame
df = pd.DataFrame(feature_list)
df['label'] = labels
df['url'] = urls

print(f"✅ Feature extraction complete!")
print(f"📊 Features extracted: {len(df.columns)-2}")
print(f"📊 Dataset shape: {df.shape}")

# Display first few rows
print("\n📋 First 5 rows of the dataset:")
print(df.head())

print("\n" + "="*50)
print("PHISHING URL DETECTION MODEL - STEP 2 COMPLETE")
print("="*50)

# Step 3: Data Analysis, Visualization, and Model Training
# Phishing URL Detection Model - Training Phase

# Set up plotting style
plt.style.use('default')
plt.rcParams['figure.figsize'] = (12, 8)

print("🔍 Starting Data Analysis and Visualization...")

# 1. Dataset Overview
print("\n📊 DATASET OVERVIEW:")
print("="*40)
print(f"Dataset Shape: {df.shape}")
print(f"Features: {len(df.columns)-2}")
print(f"Samples: {len(df)}")
print(f"\nClass Distribution:")
print(df['label'].value_counts())
print(f"Legitimate URLs: {(df['label']==0).sum()}")
print(f"Phishing URLs: {(df['label']==1).sum()}")

# 2. Feature Statistics
print("\n📈 FEATURE STATISTICS:")
print("="*40)
feature_cols = [col for col in df.columns if col not in ['label', 'url']]
print(df[feature_cols].describe())

# 3. Visualizations
print("\n🎨 Creating Visualizations...")

# Class distribution pie chart
plt.figure(figsize=(15, 5))

plt.subplot(1, 3, 1)
labels_count = df['label'].value_counts()
plt.pie(labels_count.values, labels=['Legitimate', 'Phishing'], autopct='%1.1f%%', colors=['lightgreen', 'lightcoral'])
plt.title('Class Distribution')

# URL length comparison
plt.subplot(1, 3, 2)
legitimate_lengths = df[df['label']==0]['url_length']
phishing_lengths = df[df['label']==1]['url_length']
plt.hist(legitimate_lengths, alpha=0.7, label='Legitimate', color='green', bins=10)
plt.hist(phishing_lengths, alpha=0.7, label='Phishing', color='red', bins=10)
plt.xlabel('URL Length')
plt.ylabel('Frequency')
plt.title('URL Length Distribution')
plt.legend()

# Feature correlation heatmap (top features)
plt.subplot(1, 3, 3)
top_features = ['url_length', 'domain_length', 'num_dots', 'num_hyphens', 'has_https', 'suspicious_keywords_count']
correlation_matrix = df[top_features + ['label']].corr()
sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0, fmt='.2f')
plt.title('Feature Correlation Heatmap')
plt.tight_layout()
plt.show()

# 4. Feature Importance Analysis
print("\n🔍 FEATURE IMPORTANCE ANALYSIS:")
print("="*40)

# Calculate mean values for each class
legitimate_means = df[df['label']==0][feature_cols].mean()
phishing_means = df[df['label']==1][feature_cols].mean()

print("Top 10 Features with Highest Difference:")
feature_diff = abs(legitimate_means - phishing_means).sort_values(ascending=False)
print(feature_diff.head(10))

# 5. Prepare Data for Machine Learning
print("\n🤖 PREPARING DATA FOR MACHINE LEARNING:")
print("="*40)

# Separate features and target
X = df[feature_cols]
y = df['label']

print(f"Features (X) shape: {X.shape}")
print(f"Target (y) shape: {y.shape}")

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

print(f"Training set: {X_train.shape}")
print(f"Test set: {X_test.shape}")

# Scale the features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("✅ Data preprocessing complete!")

# 6. Model Training
print("\n🚀 TRAINING MULTIPLE MODELS:")
print("="*40)

# Initialize models
models = {
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
    'Logistic Regression': LogisticRegression(random_state=42),
    'Decision Tree': DecisionTreeClassifier(random_state=42),
    'SVM': SVC(random_state=42)
}

# Train and evaluate models
model_results = {}

for name, model in models.items():
    print(f"\n🔄 Training {name}...")
    
    # Train model
    if name == 'SVM' or name == 'Logistic Regression':
        model.fit(X_train_scaled, y_train)
        y_pred = model.predict(X_test_scaled)
    else:
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
    
    # Calculate accuracy
    accuracy = accuracy_score(y_test, y_pred)
    model_results[name] = accuracy
    
    print(f"✅ {name} Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")

# 7. Best Model Selection
print("\n🏆 MODEL COMPARISON:")
print("="*40)
for name, accuracy in sorted(model_results.items(), key=lambda x: x[1], reverse=True):
    print(f"{name}: {accuracy:.4f} ({accuracy*100:.2f}%)")

best_model_name = max(model_results, key=model_results.get)
best_accuracy = model_results[best_model_name]

print(f"\n🥇 Best Model: {best_model_name}")
print(f"🎯 Best Accuracy: {best_accuracy:.4f} ({best_accuracy*100:.2f}%)")

# 8. Detailed Evaluation of Best Model
print(f"\n📊 DETAILED EVALUATION - {best_model_name}:")
print("="*40)

# Retrain the best model
best_model = models[best_model_name]
if best_model_name == 'SVM' or best_model_name == 'Logistic Regression':
    best_model.fit(X_train_scaled, y_train)
    y_pred_best = best_model.predict(X_test_scaled)
else:
    best_model.fit(X_train, y_train)
    y_pred_best = best_model.predict(X_test)

# Classification report
print("\nClassification Report:")
print(classification_report(y_test, y_pred_best, target_names=['Legitimate', 'Phishing']))

# Confusion Matrix
print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred_best)
print(cm)

# Visualize confusion matrix
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=['Legitimate', 'Phishing'], 
            yticklabels=['Legitimate', 'Phishing'])
plt.title(f'Confusion Matrix - {best_model_name}')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.show()

# 9. Feature Importance (if available)
if hasattr(best_model, 'feature_importances_'):
    print(f"\n🔍 FEATURE IMPORTANCE - {best_model_name}:")
    print("="*40)
    feature_importance = pd.DataFrame({
        'feature': feature_cols,
        'importance': best_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("Top 10 Most Important Features:")
    print(feature_importance.head(10))
    
    # Plot feature importance
    plt.figure(figsize=(10, 6))
    top_10_features = feature_importance.head(10)
    plt.barh(range(len(top_10_features)), top_10_features['importance'])
    plt.yticks(range(len(top_10_features)), top_10_features['feature'])
    plt.xlabel('Importance')
    plt.title(f'Top 10 Feature Importance - {best_model_name}')
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.show()

print("\n" + "="*50)
print("PHISHING URL DETECTION MODEL - STEP 3 COMPLETE")
print("="*50)
print("🎉 Model training successful!")
print(f"🏆 Best performing model: {best_model_name}")
print(f"🎯 Accuracy achieved: {best_accuracy*100:.2f}%")

# Step 4: Model Saving and Real URL Testing
# Phishing URL Detection Model - Model Persistence and Testing

print("💾 SAVING THE TRAINED MODEL:")
print("="*40)

# Save the best model and scaler
model_filename = 'phishing_detection_model.pkl'
scaler_filename = 'feature_scaler.pkl'

# Save the model
joblib.dump(best_model, model_filename)
print(f"✅ Model saved as: {model_filename}")

# Save the scaler
joblib.dump(scaler, scaler_filename)
print(f"✅ Scaler saved as: {scaler_filename}")

# Save feature names for consistency
feature_names = feature_cols
joblib.dump(feature_names, 'feature_names.pkl')
print(f"✅ Feature names saved as: feature_names.pkl")

# Save model metadata
model_metadata = {
    'best_model_name': best_model_name,
    'best_accuracy': best_accuracy,
    'feature_count': len(feature_cols),
    'training_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'model_type': str(type(best_model).__name__)
}
joblib.dump(model_metadata, 'model_metadata.pkl')
print(f"✅ Model metadata saved as: model_metadata.pkl")

print(f"\n🎉 All model files saved successfully!")

# Create a prediction function
def predict_phishing_url(url, model, scaler, feature_names):
    """
    Predict if a URL is phishing or legitimate
    Returns: prediction (0=legitimate, 1=phishing), confidence score, feature analysis
    """
    try:
        # Extract features
        features = extract_url_features(url)
        
        # Create feature vector in the same order as training
        feature_vector = [features.get(feature, 0) for feature in feature_names]
        feature_array = np.array(feature_vector).reshape(1, -1)
        
        # Scale features if needed
        if best_model_name in ['SVM', 'Logistic Regression']:
            feature_array = scaler.transform(feature_array)
        
        # Make prediction
        prediction = model.predict(feature_array)[0]
        
        # Get confidence score (probability)
        if hasattr(model, 'predict_proba'):
            if best_model_name in ['SVM', 'Logistic Regression']:
                proba = model.predict_proba(scaler.transform(np.array(feature_vector).reshape(1, -1)))[0]
            else:
                proba = model.predict_proba(np.array(feature_vector).reshape(1, -1))[0]
            confidence = max(proba)
        else:
            confidence = 0.8  # Default confidence for models without predict_proba
        
        return prediction, confidence, features
        
    except Exception as e:
        print(f"Error predicting URL: {str(e)}")
        return None, None, None

# Test the prediction function
print("\n🧪 TESTING THE MODEL WITH REAL URLS:")
print("="*40)

# Test URLs
test_urls = [
    'https://www.google.com',
    'https://www.paypal.com/signin',
    'http://paypal-security-verification.tk/login',
    'https://www.facebook.com/login',
    'http://192.168.1.1/secure-login',
    'https://www.amazon.com/products',
    'https://secure-amazon-account.ml/verify',
    'https://www.github.com/repositories',
    'http://microsoft-security-alert.ga/warning',
    'https://www.wikipedia.org/wiki/article'
]

print("Testing URLs:")
print("-" * 80)
print(f"{'URL':<50} {'Prediction':<15} {'Confidence':<12} {'Status'}")
print("-" * 80)

for url in test_urls:
    prediction, confidence, features = predict_phishing_url(url, best_model, scaler, feature_names)
    
    if prediction is not None:
        status = "🔒 LEGITIMATE" if prediction == 0 else "⚠️ PHISHING"
        url_display = url[:47] + "..." if len(url) > 50 else url
        print(f"{url_display:<50} {prediction:<15} {confidence:<12.2f} {status}")
    else:
        print(f"{url:<50} {'ERROR':<15} {'N/A':<12} {'❌ FAILED'}")

print("-" * 80)

# Detailed analysis for a sample phishing URL
print("\n🔍 DETAILED ANALYSIS - SAMPLE PHISHING URL:")
print("="*40)
sample_phishing_url = 'http://paypal-security-verification.tk/login'
prediction, confidence, features = predict_phishing_url(sample_phishing_url, best_model, scaler, feature_names)

if prediction is not None:
    print(f"URL: {sample_phishing_url}")
    print(f"Prediction: {'PHISHING' if prediction == 1 else 'LEGITIMATE'}")
    print(f"Confidence: {confidence:.2f}")
    print(f"\nKey Features:")
    print(f"- URL Length: {features['url_length']}")
    print(f"- Domain Length: {features['domain_length']}")
    print(f"- Has HTTPS: {'Yes' if features['has_https'] else 'No'}")
    print(f"- Suspicious TLD: {'Yes' if features['has_suspicious_tld'] else 'No'}")
    print(f"- Suspicious Keywords: {features['suspicious_keywords_count']}")
    print(f"- Number of Hyphens: {features['num_hyphens']}")
    print(f"- Has IP Address: {'Yes' if features['has_ip_address'] else 'No'}")

# Create a comprehensive prediction function for web app
def analyze_url_comprehensive(url):
    """
    Comprehensive URL analysis for web application
    Returns detailed analysis including risk factors
    """
    try:
        prediction, confidence, features = predict_phishing_url(url, best_model, scaler, feature_names)
        
        if prediction is None:
            return {
                'error': 'Failed to analyze URL',
                'status': 'error'
            }
        
        # Determine risk level
        if prediction == 0:
            if confidence > 0.8:
                risk_level = "Very Low"
                risk_color = "green"
            else:
                risk_level = "Low"
                risk_color = "lightgreen"
        else:
            if confidence > 0.8:
                risk_level = "Very High"
                risk_color = "red"
            else:
                risk_level = "High"
                risk_color = "orange"
        
        # Identify risk factors
        risk_factors = []
        if features['has_ip_address']:
            risk_factors.append("Contains IP address instead of domain name")
        if features['has_suspicious_tld']:
            risk_factors.append("Uses suspicious top-level domain")
        if not features['has_https']:
            risk_factors.append("Not using secure HTTPS protocol")
        if features['suspicious_keywords_count'] > 0:
            risk_factors.append(f"Contains {features['suspicious_keywords_count']} suspicious keywords")
        if features['url_length'] > 100:
            risk_factors.append("Unusually long URL")
        if features['num_hyphens'] > 3:
            risk_factors.append("Excessive use of hyphens")
        if features['subdomain_count'] > 2:
            risk_factors.append("Multiple subdomains detected")
        
        return {
            'url': url,
            'prediction': 'PHISHING' if prediction == 1 else 'LEGITIMATE',
            'confidence': round(confidence * 100, 2),
            'risk_level': risk_level,
            'risk_color': risk_color,
            'risk_factors': risk_factors,
            'features': features,
            'status': 'success'
        }
        
    except Exception as e:
        return {
            'error': f'Analysis failed: {str(e)}',
            'status': 'error'
        }

# Test the comprehensive analysis
print("\n📊 COMPREHENSIVE URL ANALYSIS TEST:")
print("="*40)

test_url = 'http://secure-paypal-verification.tk/signin?account=suspended'
result = analyze_url_comprehensive(test_url)

if result['status'] == 'success':
    print(f"URL: {result['url']}")
    print(f"Prediction: {result['prediction']}")
    print(f"Confidence: {result['confidence']}%")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Risk Factors ({len(result['risk_factors'])}):")
    for factor in result['risk_factors']:
        print(f"  • {factor}")
else:
    print(f"Error: {result['error']}")

# Model performance summary
print("\n📈 MODEL PERFORMANCE SUMMARY:")
print("="*40)
print(f"Model Type: {best_model_name}")
print(f"Accuracy: {best_accuracy*100:.2f}%")
print(f"Features Used: {len(feature_names)}")
print(f"Training Samples: {len(X_train)}")
print(f"Test Samples: {len(X_test)}")
print(f"Model Size: {len(joblib.dump(best_model, '/tmp/temp_model.pkl'))} bytes")

print("\n🔧 FILES CREATED FOR WEB APP:")
print("="*40)
print("1. phishing_detection_model.pkl - Trained model")
print("2. feature_scaler.pkl - Feature scaler")
print("3. feature_names.pkl - Feature names list")
print("4. model_metadata.pkl - Model information")

print("\n✅ READY FOR WEB APPLICATION DEPLOYMENT!")
print("="*50)
print("PHISHING URL DETECTION MODEL - STEP 4 COMPLETE")
print("="*50)

import gradio as gr
import joblib
import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse
import plotly.graph_objects as go
import plotly.express as px

# Load model
def load_model():
    try:
        model = joblib.load('phishing_detection_model.pkl')
        scaler = joblib.load('feature_scaler.pkl')
        feature_names = joblib.load('feature_names.pkl')
        model_metadata = joblib.load('model_metadata.pkl')
        return model, scaler, feature_names, model_metadata
    except Exception as e:
        print(f"Error loading model: {e}")
        return None, None, None, None

# Feature extraction function (same as before)
def extract_url_features(url):
    features = {}
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path
        query = parsed_url.query
        
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_questionmarks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_at_signs'] = url.count('@')
        features['num_and_signs'] = url.count('&')
        features['num_percent_signs'] = url.count('%')
        features['has_ip_address'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        features['has_suspicious_tld'] = 1 if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf']) else 0
        features['has_www'] = 1 if 'www.' in domain else 0
        features['has_https'] = 1 if url.startswith('https://') else 0
        features['subdomain_count'] = domain.count('.') - 1 if domain.count('.') > 1 else 0
        features['domain_has_numbers'] = 1 if re.search(r'\d', domain) else 0
        
        suspicious_keywords = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm']
        features['suspicious_keywords_count'] = sum(1 for keyword in suspicious_keywords if keyword in url.lower())
        
        features['has_shortening_service'] = 1 if any(service in domain for service in ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly']) else 0
        features['abnormal_url'] = 1 if re.search(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', url) else 0
        
        famous_brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'instagram', 'twitter', 'linkedin']
        features['brand_impersonation'] = 1 if any(brand in domain for brand in famous_brands) and not any(domain.endswith(f'.{brand}.com') for brand in famous_brands) else 0
        
        features['has_multiple_hyphens'] = 1 if url.count('-') > 3 else 0
        features['has_suspicious_port'] = 1 if ':' in parsed_url.netloc and not parsed_url.netloc.endswith(':80') and not parsed_url.netloc.endswith(':443') else 0
        features['url_entropy'] = calculate_entropy(url)
        
    except Exception as e:
        features = {feature: 0 for feature in ['url_length', 'domain_length', 'path_length', 'num_dots', 'num_hyphens', 
                                               'num_underscores', 'num_slashes', 'num_questionmarks', 'num_equal_signs',
                                               'num_at_signs', 'num_and_signs', 'num_percent_signs', 'has_ip_address',
                                               'has_suspicious_tld', 'has_www', 'has_https', 'subdomain_count',
                                               'domain_has_numbers', 'suspicious_keywords_count', 'has_shortening_service',
                                               'abnormal_url', 'brand_impersonation', 'has_multiple_hyphens',
                                               'has_suspicious_port', 'url_entropy']}
    
    return features

def calculate_entropy(text):
    if not text:
        return 0
    prob = [float(text.count(c))/len(text) for c in dict.fromkeys(list(text))]
    entropy = sum([-p * np.log2(p) for p in prob if p > 0])
    return entropy

# Load model globally
model, scaler, feature_names, model_metadata = load_model()

def analyze_url_gradio(url):
    """Main function for Gradio interface"""
    if not url:
        return "Please enter a URL", "", "", ""
    
    if model is None:
        return "Model not loaded", "", "", ""
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        # Extract features
        features = extract_url_features(url)
        
        # Create feature vector
        feature_vector = [features.get(feature, 0) for feature in feature_names]
        feature_array = np.array(feature_vector).reshape(1, -1)
        
        # Scale features if needed
        if model_metadata['best_model_name'] in ['SVM', 'Logistic Regression']:
            feature_array = scaler.transform(feature_array)
        
        # Make prediction
        prediction = model.predict(feature_array)[0]
        
        # Get confidence score
        if hasattr(model, 'predict_proba'):
            proba = model.predict_proba(feature_array)[0]
            confidence = max(proba)
        else:
            confidence = 0.8
        
        # Determine result
        if prediction == 1:
            result = "🚨 PHISHING DETECTED"
            risk_level = "HIGH RISK"
            color = "red"
        else:
            result = "✅ LEGITIMATE URL"
            risk_level = "LOW RISK"
            color = "green"
        
        # Get risk factors
        risk_factors = []
        if features['has_ip_address']:
            risk_factors.append("• Contains IP address")
        if features['has_suspicious_tld']:
            risk_factors.append("• Suspicious TLD")
        if not features['has_https']:
            risk_factors.append("• No HTTPS")
        if features['suspicious_keywords_count'] > 0:
            risk_factors.append(f"• {features['suspicious_keywords_count']} suspicious keywords")
        if features['url_length'] > 100:
            risk_factors.append("• Long URL")
        if features['num_hyphens'] > 3:
            risk_factors.append("• Excessive hyphens")
        if features['subdomain_count'] > 2:
            risk_factors.append("• Multiple subdomains")
        if features['brand_impersonation']:
            risk_factors.append("• Brand impersonation")
        
        risk_text = "\n".join(risk_factors) if risk_factors else "No major risk factors detected"
        
        # Feature summary
        feature_summary = f"""
        📊 **Feature Analysis:**
        • URL Length: {features['url_length']} characters
        • Domain Length: {features['domain_length']} characters
        • Number of Dots: {features['num_dots']}
        • Number of Hyphens: {features['num_hyphens']}
        • Suspicious Keywords: {features['suspicious_keywords_count']}
        • Subdomains: {features['subdomain_count']}
        • HTTPS: {'Yes' if features['has_https'] else 'No'}
        • IP Address: {'Yes' if features['has_ip_address'] else 'No'}
        """
        
        return result, f"Confidence: {confidence:.2%}", risk_text, feature_summary
        
    except Exception as e:
        return f"Error analyzing URL: {str(e)}", "", "", ""

# Create Gradio interface
def create_interface():
    with gr.Blocks(title="Phishing URL Detection", theme=gr.themes.Soft()) as demo:
        gr.Markdown("""
        # 🛡️ Phishing URL Detection System
        ### AI-powered URL security analysis using Machine Learning
        
        Enter a URL below to check if it's legitimate or potentially phishing.
        """)
        
        with gr.Row():
            with gr.Column(scale=3):
                url_input = gr.Textbox(
                    label="🔗 Enter URL to analyze",
                    placeholder="https://example.com",
                    lines=1
                )
            with gr.Column(scale=1):
                analyze_btn = gr.Button("🔍 Analyze URL", variant="primary")
        
        # Sample URLs
        gr.Markdown("### 📋 Sample URLs for Testing:")
        with gr.Row():
            with gr.Column():
                gr.Markdown("**Legitimate URLs:**")
                sample_legit = gr.Examples(
                    examples=[
                        ["https://www.google.com"],
                        ["https://www.github.com"],
                        ["https://www.amazon.com"],
                        ["https://www.microsoft.com"]
                    ],
                    inputs=url_input,
                    label=""
                )
            with gr.Column():
                gr.Markdown("**Suspicious URLs:**")
                sample_phish = gr.Examples(
                    examples=[
                        ["http://paypal-security.com"],
                        ["https://amazon-login.tk"],
                        ["http://192.168.1.1/login.php"],
                        ["https://bit.ly/fake-bank"]
                    ],
                    inputs=url_input,
                    label=""
                )
        
        # Results
        with gr.Row():
            with gr.Column():
                result_output = gr.Textbox(label="🎯 Analysis Result", lines=1)
                confidence_output = gr.Textbox(label="📊 Confidence Score", lines=1)
            with gr.Column():
                risk_output = gr.Textbox(label="⚠️ Risk Factors", lines=5)
                features_output = gr.Textbox(label="📈 Feature Analysis", lines=8)
        
        # Model info
        if model_metadata:
            gr.Markdown(f"""
            ### 🤖 Model Information:
            - **Algorithm:** {model_metadata['best_model_name']}
            - **Accuracy:** {model_metadata['best_accuracy']:.2%}
            - **Features:** {len(feature_names)}
            """)
        
        # Event handlers
        analyze_btn.click(
            analyze_url_gradio,
            inputs=[url_input],
            outputs=[result_output, confidence_output, risk_output, features_output]
        )
        
        url_input.submit(
            analyze_url_gradio,
            inputs=[url_input],
            outputs=[result_output, confidence_output, risk_output, features_output]
        )
    
    return demo

# Create and launch the interface
demo = create_interface()

# Launch with public link (works in Colab)
demo.launch(share=True, debug=False)

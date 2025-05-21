import streamlit as st
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from pyzbar.pyzbar import decode
import cv2
from PIL import Image
import io
import threading

# Load the pre-trained model (voting_classifier_model.pkl)
model = joblib.load('voting_classifier_model.pkl')

import re
from urllib.parse import urlparse

def extract_features(url):
    features = []

    # Feature 1: Length of URL
    features.append(len(url))

    # Feature 2: Count of '.'
    features.append(url.count('.'))

    # Feature 3: Count of '@'
    features.append(url.count('@'))

    # Feature 4: Count of '?'
    features.append(url.count('?'))

    # Feature 5: Count of '-'
    features.append(url.count('-'))

    # Feature 6: Count of '='
    features.append(url.count('='))

    # Feature 7: Count of 'http'
    features.append(url.count('http'))

    # Feature 8: Count of 'https'
    features.append(url.count('https'))

    # Feature 9: Count of 'www'
    features.append(url.count('www'))

    # Feature 10: Count of digits in URL
    digits = sum(c.isdigit() for c in url)
    features.append(digits)

    # Feature 11: Count of letters in URL
    letters = sum(c.isalpha() for c in url)
    features.append(letters)

    # Feature 12: Number of directories in URL path
    path = urlparse(url).path
    features.append(path.count('/'))

    # Feature 13: Count of '//'
    features.append(url.count('//'))

    # Feature 14: Count of '%'
    features.append(url.count('%'))

    # Feature 15: Count of '.com'
    features.append(url.count('.com'))

    # Feature 16: Count of '.exe'
    features.append(url.count('.exe'))

    # Feature 17: Count of '.php'
    features.append(url.count('.php'))

    # Feature 18: Is IP address used instead of domain (1 = yes, 0 = no)
    domain = urlparse(url).netloc
    features.append(1 if re.fullmatch(r'(\d{1,3}\.){3}\d{1,3}', domain) else 0)

    # Feature 19: Length of domain
    features.append(len(domain))

    # Feature 20: Count of subdomains
    features.append(domain.count('.') - 1)

    # Feature 21: Presence of HTTPS (1 = yes, 0 = no)
    features.append(1 if url.startswith("https") else 0)

    # Feature 22: Is domain in known suspicious TLDs?
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
    features.append(1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0)

    # Feature 23–31: Placeholder values (adjust if your training data uses others)
    for _ in range(31 - len(features)):
        features.append(0)

    return features

# Function to preprocess and predict if the URL is phishing or benign
def predict_url(url_features):
    prediction = model.predict([url_features])
    return prediction[0]


# Function to handle QR code scanning from image
def scan_qr_code(image):
    qr_codes = decode(image)
    urls = []
    for qr in qr_codes:
        qr_data = qr.data.decode('utf-8')
        urls.append(qr_data)
    return urls

# Set the title and instructions
st.title("Phishing URL and QR Code Scanner")
st.markdown("### Upload a URL or QR code image to check if it's phishing or safe.")

# URL Prediction Section
st.header("Predict Phishing URL")
url_input = st.text_input("Enter URL:")
if url_input:
    # You would have feature extraction logic here for the URL
    # For simplicity, let's assume you already have the features extracted for the URL
    # Example: [length_of_url, number_of_subdomains, etc.]
    url_features = extract_features(url_input)
    prediction = predict_url(url_features)
    if prediction == 1:
        st.success("This URL is SAFE.")
    else:
        st.error("This URL is PHISHING.")

# QR Code Image Upload Section
st.header("Upload QR Code Image to Scan")
qr_code_image = st.file_uploader("Upload QR code image", type=["png", "jpg", "jpeg"])
if qr_code_image:
    image = Image.open(qr_code_image).convert('RGB')  # Ensure RGB
    st.image(image, caption="Uploaded QR Code", use_container_width=True)
    
    image_np = np.array(image)
    image_bgr = cv2.cvtColor(image_np, cv2.COLOR_RGB2BGR)  # OpenCV format

    # Scan QR code in the uploaded image
    urls_in_qr = scan_qr_code(image_bgr)
    if urls_in_qr:
        for url in urls_in_qr:
            st.write(f"URL found in QR Code: {url}")
            url_features = extract_features(url)
            prediction = predict_url(url_features)
            if prediction == 1:
                st.success("This URL is SAFE.")
            else:
                st.error("This URL is PHISHING.")
    else:
        st.error("No QR code detected.")


# Live QR Code Scanning Section
st.header("Live QR Code Scanner")

# Shared state to control the scanner loop
if "scan_active" not in st.session_state:
    st.session_state.scan_active = False
if "last_qr_data" not in st.session_state:
    st.session_state.last_qr_data = ""

# Start scan button
if st.button("Start QR Scan"):
    st.session_state.scan_active = True
    st.info("Webcam started. Waiting for QR code...")

# Stop scan button
if st.button("Stop Scan"):
    st.session_state.scan_active = False
    st.warning("QR scan stopped.")

# Scanner logic
if st.session_state.scan_active:
    cap = cv2.VideoCapture(0)
    frame_display = st.empty()
    scan_results = st.empty()
    qr_preview = st.empty()

    while st.session_state.scan_active:
        ret, frame = cap.read()
        if not ret:
            scan_results.warning("Failed to access webcam.")
            break

        decoded_qr_codes = decode(frame)
        if decoded_qr_codes:
            for qr in decoded_qr_codes:
                qr_data = qr.data.decode('utf-8')

                # Show decoded link live
                st.session_state.last_qr_data = qr_data
                qr_preview.markdown(f"**🔗 Live QR Code Decoded URL:** `{qr_data}`")

                # Make prediction
                url_features = extract_features(qr_data)
                prediction = predict_url(url_features)
                if prediction == 1:
                    scan_results.success("✅ This URL is SAFE.")
                else:
                    scan_results.error("🚨 This URL is PHISHING.")
            st.session_state.scan_active = False  # Auto-stop after success
            break

        frame_display.image(frame, channels="BGR", caption="Live QR Feed", use_container_width=True)

    cap.release()
    st.success("QR scan complete.")

# Show last scanned link even after scan stops
if st.session_state.last_qr_data and not st.session_state.scan_active:
    st.markdown(f"**🔍 Last Decoded QR Code URL:** `{st.session_state.last_qr_data}`")

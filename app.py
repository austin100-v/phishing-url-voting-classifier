import streamlit as st
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from pyzbar.pyzbar import decode
from PIL import Image
import io
import re
from urllib.parse import urlparse

# Load the pre-trained model
model = joblib.load('voting_classifier_model.pkl')

def extract_features(url):
    features = []

    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('@'))
    features.append(url.count('?'))
    features.append(url.count('-'))
    features.append(url.count('='))
    features.append(url.count('http'))
    features.append(url.count('https'))
    features.append(url.count('www'))
    digits = sum(c.isdigit() for c in url)
    features.append(digits)
    letters = sum(c.isalpha() for c in url)
    features.append(letters)
    path = urlparse(url).path
    features.append(path.count('/'))
    features.append(url.count('//'))
    features.append(url.count('%'))
    features.append(url.count('.com'))
    features.append(url.count('.exe'))
    features.append(url.count('.php'))
    domain = urlparse(url).netloc
    features.append(1 if re.fullmatch(r'(\d{1,3}\.){3}\d{1,3}', domain) else 0)
    features.append(len(domain))
    features.append(domain.count('.') - 1)
    features.append(1 if url.startswith("https") else 0)
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
    features.append(1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0)

    for _ in range(31 - len(features)):
        features.append(0)

    return features

def is_valid_url(data: str) -> bool:
    try:
        result = urlparse(data)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except:
        return False

def predict_url(url_features):
    prediction = model.predict([url_features])
    return prediction[0]

# NEW: Use pyzbar for QR code detection
def scan_qr_code(image_np):
    decoded_objs = decode(image_np)
    return [obj.data.decode('utf-8') for obj in decoded_objs if obj.data]

# Initialize session state
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

st.title("Phishing URL and QR Code Scanner")
st.markdown("### Upload a URL or QR code image to check if it's phishing or safe.")

# Manual URL Input
st.header("Predict Phishing URL")
url_input = st.text_input("Enter URL:")
if url_input:
    url_features = extract_features(url_input)
    prediction = predict_url(url_features)
    result = "SAFE" if prediction == 1 else "PHISHING"
    if prediction == 1:
        st.success("This URL is SAFE.")
    else:
        st.error("This URL is PHISHING.")
    st.session_state.scan_history.append((url_input, result))

# QR Code Image Upload
st.header("Upload QR Code Image to Scan")
qr_code_image = st.file_uploader("Upload QR code image", type=["png", "jpg", "jpeg"])
if qr_code_image:
    image = Image.open(qr_code_image).convert('RGB')
    st.image(image, caption="Uploaded QR Code", use_container_width=True)

    image_np = np.array(image)
    urls_in_qr = scan_qr_code(image_np)
    if urls_in_qr:
        for data in urls_in_qr:
            st.write(f"QR Code Content: {data}")
            st.code(data)
            st.download_button("Copy QR Content", data, file_name="qr_content.txt")
            if is_valid_url(data):
                url_features = extract_features(data)
                prediction = predict_url(url_features)
                result = "SAFE" if prediction == 1 else "PHISHING"
                if prediction == 1:
                    st.success("This URL is SAFE.")
                else:
                    st.error("This URL is PHISHING.")
                st.session_state.scan_history.append((data, result))
            else:
                st.warning("⚠️ This QR code does not contain a valid URL.")
    else:
        st.error("No QR code detected. Try another image or use a clearer code.")

# Scan History
if st.session_state.scan_history:
    st.header("Scan History")
    history_df = pd.DataFrame(st.session_state.scan_history, columns=["Content", "Prediction"])
    st.dataframe(history_df, use_container_width=True)
    

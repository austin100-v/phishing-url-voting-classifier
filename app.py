import streamlit as st
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import re

# Load model
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

# Streamlit UI
st.title("Phishing URL and QR Code Scanner (with Live Camera)")

st.header("Enter URL Manually")
url_input = st.text_input("Enter URL:")
if url_input:
    features = extract_features(url_input)
    pred = predict_url(features)
    if pred == 1:
        st.success("This URL is SAFE.")
    else:
        st.error("This URL is PHISHING.")

# Hidden input to receive scanned QR code data from JS
qr_data = st.text_input("QR Code Data (hidden)", key="qr_data", value="", label_visibility="collapsed")

if qr_data:
    st.markdown(f"**Scanned QR Code Content:** `{qr_data}`")
    if is_valid_url(qr_data):
        features = extract_features(qr_data)
        pred = predict_url(features)
        if pred == 1:
            st.success("✅ This URL is SAFE.")
        else:
            st.error("🚨 This URL is PHISHING.")
    else:
        st.warning("⚠️ This QR code does not contain a valid URL.")

# Inject html5-qrcode for live scanning
st.header("Live QR Code Scanner")

# JavaScript and HTML for live camera scan via html5-qrcode
# When QR detected, JS sets the hidden input value so Streamlit can react
st.components.v1.html("""
<!DOCTYPE html>
<html>
<head>
  <script src="https://unpkg.com/html5-qrcode" type="text/javascript"></script>
</head>
<body>
  <div id="reader" style="width: 300px;"></div>
  <script>
    function sendToStreamlit(data) {
      const inputBox = window.parent.document.querySelector('input[data-baseweb="true"][aria-label="QR Code Data (hidden)"]');
      if (inputBox) {
        inputBox.value = data;
        inputBox.dispatchEvent(new Event('input', { bubbles: true }));
      }
    }
    let lastResult = null;
    function onScanSuccess(decodedText, decodedResult) {
      if (decodedText !== lastResult) {
        lastResult = decodedText;
        sendToStreamlit(decodedText);
      }
    }
    var html5QrcodeScanner = new Html5QrcodeScanner(
      "reader", { fps: 10, qrbox: 250 });
    html5QrcodeScanner.render(onScanSuccess);
  </script>
</body>
</html>
""", height=400)

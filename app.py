import streamlit as st
import joblib
import numpy as np
import pandas as pd
from PIL import Image
import cv2
from urllib.parse import urlparse
import re
import streamlit.components.v1 as components

# Load model
model = joblib.load('voting_classifier_model.pkl')

# Extract features from URL
def extract_features(url):
    features = [
        len(url),
        url.count('.'),
        url.count('@'),
        url.count('?'),
        url.count('-'),
        url.count('='),
        url.count('http'),
        url.count('https'),
        url.count('www'),
        sum(c.isdigit() for c in url),
        sum(c.isalpha() for c in url),
        urlparse(url).path.count('/'),
        url.count('//'),
        url.count('%'),
        url.count('.com'),
        url.count('.exe'),
        url.count('.php'),
        1 if re.fullmatch(r'(\d{1,3}\.){3}\d{1,3}', urlparse(url).netloc) else 0,
        len(urlparse(url).netloc),
        urlparse(url).netloc.count('.') - 1,
        1 if url.startswith("https") else 0,
        1 if any(urlparse(url).netloc.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']) else 0,
    ]
    while len(features) < 31:
        features.append(0)
    return features

def predict_url(features):
    prediction = model.predict([features])
    return prediction[0]

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return all([parsed.scheme in ['http', 'https'], parsed.netloc])
    except:
        return False

def scan_qr_code(image):
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(image)
    return [data] if data else []

# Initialize state
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

# Title and Description
st.title("Phishing URL and QR Code Scanner")
st.markdown("### Upload a URL or QR code image or scan live to check if it's phishing or safe.")

# URL Input
st.header("Predict Phishing URL")
url_input = st.text_input("Enter URL:")
if url_input:
    features = extract_features(url_input)
    prediction = predict_url(features)
    result = "SAFE" if prediction == 1 else "PHISHING"
    st.success("This URL is SAFE.") if prediction == 1 else st.error("This URL is PHISHING.")
    st.session_state.scan_history.append((url_input, result))

# QR Image Upload
st.header("Upload QR Code Image")
qr_file = st.file_uploader("Upload QR image", type=["png", "jpg", "jpeg"])
if qr_file:
    image = Image.open(qr_file).convert('RGB')
    st.image(image, caption="Uploaded QR Code", use_container_width=True)
    np_image = np.array(image)
    np_image = cv2.cvtColor(np_image, cv2.COLOR_RGB2BGR)
    qr_data = scan_qr_code(np_image)
    if qr_data:
        for data in qr_data:
            st.write("QR Code Content:")
            st.code(data)
            st.download_button("Copy QR Content", data, file_name="qr_content.txt")
            if is_valid_url(data):
                features = extract_features(data)
                prediction = predict_url(features)
                result = "SAFE" if prediction == 1 else "PHISHING"
                st.success("This URL is SAFE.") if prediction == 1 else st.error("This URL is PHISHING.")
                st.session_state.scan_history.append((data, result))
            else:
                st.warning("⚠️ This QR code does not contain a valid URL.")
    else:
        st.error("No QR code detected.")

# Live QR Code Scanner
st.header("Live QR Code Scanner (Web-Compatible)")

qr_scanner = """
<div id="reader" style="width:100%"></div>
<script src="https://unpkg.com/html5-qrcode"></script>
<script>
const html5QrCode = new Html5Qrcode("reader");
html5QrCode.start(
  { facingMode: "environment" },
  {
    fps: 10,
    qrbox: 250
  },
  (decodedText, decodedResult) => {
    const streamlitInput = window.parent.document.querySelector('iframe').contentWindow;
    streamlitInput.postMessage({isStreamlitMessage: true, type: "streamlit:setComponentValue", data: decodedText}, "*");
    html5QrCode.stop();
  },
  (errorMessage) => {}
).catch(err => {
  console.error("Camera error:", err);
});
</script>
"""

qr_result = components.html(qr_scanner, height=400)

# Receive QR result
if '_qr_result' not in st.session_state:
    st.session_state._qr_result = ""

qr_input = st.text_input("Scanned QR content will appear here:", st.session_state._qr_result, key="live_qr")

if qr_input and qr_input != st.session_state._qr_result:
    st.session_state._qr_result = qr_input
    st.markdown(f"**Scanned QR Code Content:** `{qr_input}`")
    st.code(qr_input)
    st.download_button("Copy QR Content", qr_input, file_name="qr_content.txt")
    if is_valid_url(qr_input):
        features = extract_features(qr_input)
        prediction = predict_url(features)
        result = "SAFE" if prediction == 1 else "PHISHING"
        st.success("✅ This URL is SAFE.") if prediction == 1 else st.error("🚨 This URL is PHISHING.")
        st.session_state.scan_history.append((qr_input, result))
    else:
        st.warning("⚠️ This QR code does not contain a valid URL.")

# History
if st.session_state.scan_history:
    st.header("Scan History")
    df = pd.DataFrame(st.session_state.scan_history, columns=["Content", "Prediction"])
    st.dataframe(df, use_container_width=True)

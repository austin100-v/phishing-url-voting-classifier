import streamlit as st
import joblib
import numpy as np
import pandas as pd
from PIL import Image
import cv2
from urllib.parse import urlparse
import re
import streamlit.components.v1 as components

# Load your trained model
model = joblib.load('voting_classifier_model.pkl')

# Helper functions
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
    return model.predict([features])[0]

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ['http', 'https'] and bool(parsed.netloc)
    except:
        return False

def scan_qr_code(image):
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(image)
    return [data] if data else []

# Session state
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

# Page layout
st.title("Phishing URL and QR Code Scanner")
st.markdown("### Upload a URL, QR image or scan live to detect phishing threats.")

# --- URL Input ---
st.header("Predict Phishing URL")
url_input = st.text_input("Enter URL:")
if url_input:
    features = extract_features(url_input)
    result = "SAFE" if predict_url(features) == 1 else "PHISHING"
    st.success("This URL is SAFE.") if result == "SAFE" else st.error("This URL is PHISHING.")
    st.session_state.scan_history.append((url_input, result))

# --- QR Image Upload ---
st.header("Upload QR Code Image")
qr_file = st.file_uploader("Upload QR image", type=["png", "jpg", "jpeg"])
if qr_file:
    image = Image.open(qr_file).convert('RGB')
    st.image(image, caption="Uploaded QR Code", use_container_width=True)
    image_np = np.array(image)
    image_bgr = cv2.cvtColor(image_np, cv2.COLOR_RGB2BGR)
    qr_data = scan_qr_code(image_bgr)
    if qr_data:
        for data in qr_data:
            st.write("QR Code Content:")
            st.code(data)
            st.download_button("Copy QR Content", data, file_name="qr_content.txt")
            if is_valid_url(data):
                features = extract_features(data)
                result = "SAFE" if predict_url(features) == 1 else "PHISHING"
                st.success("This URL is SAFE.") if result == "SAFE" else st.error("This URL is PHISHING.")
                st.session_state.scan_history.append((data, result))
            else:
                st.warning("⚠️ This QR code does not contain a valid URL.")
    else:
        st.error("No QR code detected.")

# --- Live QR Scanner (Web-Compatible) ---
st.header("Live QR Code Scanner (Browser Camera)")

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
    const inputBox = window.parent.document.querySelector('iframe').contentWindow;
    inputBox.postMessage({isStreamlitMessage: true, type: "streamlit:setComponentValue", data: decodedText}, "*");
    html5QrCode.stop();
  },
  (errorMessage) => {}
).catch(err => {
  console.error("Camera error:", err);
});
</script>
"""

components.html(qr_scanner, height=400)

# Receive scanned data
if "_qr_result" not in st.session_state:
    st.session_state._qr_result = ""

qr_input = st.text_input("Scanned QR content will appear here:", st.session_state._qr_result, key="live_qr")

if qr_input and qr_input != st.session_state._qr_result:
    st.session_state._qr_result = qr_input
    st.markdown(f"**Scanned QR Code Content:** `{qr_input}`")
    st.code(qr_input)
    st.download_button("Copy QR Content", qr_input, file_name="qr_content.txt")
    if is_valid_url(qr_input):
        features = extract_features(qr_input)
        result = "SAFE" if predict_url(features) == 1 else "PHISHING"
        st.success("✅ This URL is SAFE.") if result == "SAFE" else st.error("🚨 This URL is PHISHING.")
        st.session_state.scan_history.append((qr_input, result))
    else:
        st.warning("⚠️ This QR code does not contain a valid URL.")

# --- Scan History ---
if st.session_state.scan_history:
    st.header("Scan History")
    history_df = pd.DataFrame(st.session_state.scan_history, columns=["Content", "Prediction"])
    st.dataframe(history_df, use_container_width=True)
    

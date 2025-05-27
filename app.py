import streamlit as st
import joblib
import numpy as np
from urllib.parse import urlparse
import re
from PIL import Image
import cv2

# Load your pre-trained model
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
        return bool(result.scheme) and bool(result.netloc) or data.startswith("upi://")
    except:
        return False

def predict_url(url_features):
    prediction = model.predict([url_features])
    return prediction[0]

def scan_qr_code(image):
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(image)
    return data

st.title("Phishing URL and QR Code Scanner")

# Manual URL input
url_input = st.text_input("Enter URL to check:")
if url_input:
    features = extract_features(url_input)
    pred = predict_url(features)
    if pred == 1:
        st.success("✅ This URL is SAFE.")
    else:
        st.error("🚨 This URL is PHISHING.")

# QR code image upload
st.header("Upload QR Code Image")
qr_image_file = st.file_uploader("Upload QR code image", type=['png', 'jpg', 'jpeg'])
if qr_image_file:
    image = Image.open(qr_image_file).convert('RGB')
    st.image(image, caption="Uploaded QR Code", use_container_width=True)
    image_np = np.array(image)
    image_bgr = cv2.cvtColor(image_np, cv2.COLOR_RGB2BGR)
    qr_data = scan_qr_code(image_bgr)

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
    else:
        st.error("No QR code detected in the uploaded image.")

# ----------------- LIVE SCAN SECTION -----------------
st.header("Live QR Code Scanner")

# Session state flags
if "scanning" not in st.session_state:
    st.session_state.scanning = False
if "scanned" not in st.session_state:
    st.session_state.scanned = False
if "live_qr_data" not in st.session_state:
    st.session_state.live_qr_data = ""

# Start/Stop Scan Buttons
col1, col2 = st.columns(2)
with col1:
    if st.button("Start Scan", key="live_start"):
        st.session_state.scanning = True
        st.session_state.scanned = False
with col2:
    if st.button("Stop Scan", key="live_stop"):
        st.session_state.scanning = False

# QR Scanner HTML
if st.session_state.scanning:
    st.text_input("QR Code Data", key="live_qr_data", label_visibility="collapsed", on_change=lambda: st.session_state.update({"scanned": True}))
    st.components.v1.html(f"""
    <script src="https://unpkg.com/html5-qrcode" type="text/javascript"></script>
    <div id="reader" style="width: 300px;"></div>
    <script>
      let lastResult = null;
      let scanner = new Html5QrcodeScanner("reader", {{ fps: 10, qrbox: 250 }});
      scanner.render(function(decodedText, decodedResult) {{
        if (decodedText !== lastResult) {{
          lastResult = decodedText;
          const inputBox = window.parent.document.querySelector('input[data-baseweb="input"]');
          if (inputBox) {{
            inputBox.value = decodedText;
            inputBox.dispatchEvent(new Event('input', {{ bubbles: true }}));
          }}
        }}
      }});
    </script>
    """, height=450)

# Show scan result
def handle_scanned_data():
    qr_data = st.session_state.live_qr_data
    if qr_data:
        st.markdown(f"**Scanned QR Code Content (Live):** `{qr_data}`")
        if is_valid_url(qr_data):
            features = extract_features(qr_data)
            pred = predict_url(features)
            if pred == 1:
                st.success("✅ This URL is SAFE.")
            else:
                st.error("🚨 This URL is PHISHING.")
        else:
            st.warning("⚠️ This QR code does not contain a valid URL.")

if st.session_state.scanned:
    handle_scanned_data()

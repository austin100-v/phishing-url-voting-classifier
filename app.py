import streamlit as st
import joblib
import numpy as np
from urllib.parse import urlparse
import re
from PIL import Image
import cv2

# Load model
model = joblib.load('voting_classifier_model.pkl')

def extract_features(url):
    features = [
        len(url), url.count('.'), url.count('@'), url.count('?'), url.count('-'),
        url.count('='), url.count('http'), url.count('https'), url.count('www'),
        sum(c.isdigit() for c in url), sum(c.isalpha() for c in url),
        urlparse(url).path.count('/'), url.count('//'), url.count('%'),
        url.count('.com'), url.count('.exe'), url.count('.php')
    ]
    domain = urlparse(url).netloc
    features.extend([
        1 if re.fullmatch(r'(\d{1,3}\.){3}\d{1,3}', domain) else 0,
        len(domain), domain.count('.') - 1,
        1 if url.startswith("https") else 0,
        1 if any(domain.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']) else 0
    ])
    while len(features) < 31:
        features.append(0)
    return features

def is_valid_url(data):
    try:
        result = urlparse(data)
        return all([result.scheme in ['http', 'https', 'upi'], result.netloc or result.path])
    except:
        return False

def predict_url(features):
    return model.predict([features])[0]

def scan_qr_code(image):
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(image)
    return data

st.title("Phishing URL and QR Code Scanner")

# Manual URL check
url_input = st.text_input("Enter URL to check:")
if url_input:
    features = extract_features(url_input)
    pred = predict_url(features)
    if pred == 1:
        st.success("✅ This URL is SAFE.")
    else:
        st.error("🚨 This URL is PHISHING.")

# QR image upload
st.header("Upload QR Code Image")
uploaded_img = st.file_uploader("Upload QR code image", type=['png', 'jpg', 'jpeg'])
if uploaded_img:
    image = Image.open(uploaded_img).convert('RGB')
    st.image(image, caption="Uploaded QR Code", use_container_width=True)
    image_np = np.array(image)
    image_bgr = cv2.cvtColor(image_np, cv2.COLOR_RGB2BGR)
    data = scan_qr_code(image_bgr)

    if data:
        st.markdown(f"**Scanned QR Code Content:** `{data}`")
        if is_valid_url(data):
            features = extract_features(data)
            pred = predict_url(features)
            if pred == 1:
                st.success("✅ This URL is SAFE.")
            else:
                st.error("🚨 This URL is PHISHING.")
        else:
            st.warning("⚠️ This QR code does not contain a valid URL.")
    else:
        st.error("No QR code detected in the uploaded image.")

# Live QR scanning
st.header("Live QR Code Scanner")
stop = st.button("Stop Scan")
st.components.v1.html("""
<div id=\"reader\" style=\"width:300px;\"></div>
<script src=\"https://unpkg.com/html5-qrcode\"></script>
<script>
    const reader = new Html5QrcodeScanner("reader", { fps: 10, qrbox: 250 });
    function sendToStreamlit(text) {
        const input = window.parent.document.querySelector('input[aria-label="QR Code Data (live)"]');
        if (input) {
            input.value = text;
            input.dispatchEvent(new Event('input', { bubbles: true }));
        }
    }
    let lastResult = null;
    reader.render((decodedText) => {
        if (decodedText !== lastResult) {
            lastResult = decodedText;
            sendToStreamlit(decodedText);
        }
    });
</script>
""", height=400)

qr_live_data = st.text_input("QR Code Data (live)", value="", label_visibility="collapsed")
if qr_live_data and not stop:
    st.markdown(f"**Live QR Code Result:** `{qr_live_data}`")
    if is_valid_url(qr_live_data):
        features = extract_features(qr_live_data)
        pred = predict_url(features)
        if pred == 1:
            st.success("✅ This URL is SAFE.")
        else:
            st.error("🚨 This URL is PHISHING.")
    else:
        st.warning("⚠️ This QR code does not contain a valid URL.")
        

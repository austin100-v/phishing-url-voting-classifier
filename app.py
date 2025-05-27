import streamlit as st import joblib import numpy as np import pandas as pd from sklearn.preprocessing import StandardScaler import cv2 from PIL import Image import io import threading

Load the pre-trained model (voting_classifier_model.pkl)

model = joblib.load('voting_classifier_model.pkl')

import re from urllib.parse import urlparse

def extract_features(url): features = []

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

def is_valid_url(data: str) -> bool: try: result = urlparse(data) return all([result.scheme in ['http', 'https'], result.netloc]) except: return False

def predict_url(url_features): prediction = model.predict([url_features]) return prediction[0]

def scan_qr_code(image): detector = cv2.QRCodeDetector() data, points, _ = detector.detectAndDecode(image) return [data] if data else []

Initialize session state for scan history

if "scan_history" not in st.session_state: st.session_state.scan_history = []

st.title("Phishing URL and QR Code Scanner") st.markdown("### Upload a URL or QR code image to check if it's phishing or safe.")

st.header("Predict Phishing URL") url_input = st.text_input("Enter URL:") if url_input: url_features = extract_features(url_input) prediction = predict_url(url_features) result = "SAFE" if prediction == 1 else "PHISHING" if prediction == 1: st.success("This URL is SAFE.") else: st.error("This URL is PHISHING.") st.session_state.scan_history.append((url_input, result))

st.header("Upload QR Code Image to Scan") qr_code_image = st.file_uploader("Upload QR code image", type=["png", "jpg", "jpeg"]) if qr_code_image: image = Image.open(qr_code_image).convert('RGB') st.image(image, caption="Uploaded QR Code", use_container_width=True)

image_np = np.array(image)
image_bgr = cv2.cvtColor(image_np, cv2.COLOR_RGB2BGR)

urls_in_qr = scan_qr_code(image_bgr)
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
    st.error("No QR code detected.")

st.header("Live QR Code Scanner")

if "scan_active" not in st.session_state: st.session_state.scan_active = False if "last_qr_data" not in st.session_state: st.session_state.last_qr_data = ""

if st.button("Start QR Scan"): st.session_state.scan_active = True st.info("Webcam started. Waiting for QR code...")

if st.button("Stop Scan"): st.session_state.scan_active = False st.warning("QR scan stopped.")

if st.session_state.scan_active: cap = cv2.VideoCapture(0) frame_display = st.empty() scan_results = st.empty() qr_preview = st.empty()

detector = cv2.QRCodeDetector()

while st.session_state.scan_active:
    ret, frame = cap.read()
    if not ret:
        scan_results.warning("Failed to access webcam.")
        break

    data, points, _ = detector.detectAndDecode(frame)
    if data:
        st.session_state.last_qr_data = data
        qr_preview.markdown(f"**🔗 Live QR Code Decoded Content:** `{data}`")
        st.code(data)
        st.download_button("Copy QR Content", data, file_name="qr_content.txt")
        if is_valid_url(data):
            url_features = extract_features(data)
            prediction = predict_url(url_features)
            result = "SAFE" if prediction == 1 else "PHISHING"
            if prediction == 1:
                scan_results.success("✅ This URL is SAFE.")
            else:
                scan_results.error("🚨 This URL is PHISHING.")
            st.session_state.scan_history.append((data, result))
        else:
            scan_results.warning("⚠️ This QR code does not contain a valid URL.")
        st.session_state.scan_active = False
        break

    frame_display.image(frame, channels="BGR", caption="Live QR Feed", use_container_width=True)

cap.release()
st.success("QR scan complete.")

if st.session_state.last_qr_data and not st.session_state.scan_active: st.markdown(f"🔍 Last Decoded QR Code Content: {st.session_state.last_qr_data}")

Scan History Table

if st.session_state.scan_history: st.header("Scan History") history_df = pd.DataFrame(st.session_state.scan_history, columns=["Content", "Prediction"]) st.dataframe(history_df, use_container_width=True)


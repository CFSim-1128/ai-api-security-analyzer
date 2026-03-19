import streamlit as st
import requests

st.set_page_config(page_title="AI API Security Analyzer", layout="wide")
st.title("AI API Security Analyzer")

url = st.text_input("API URL")
method = st.selectbox("HTTP Method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
token = st.text_area("JWT Token (optional)")
body_text = st.text_area("JSON Body (optional)", value="{}")

if st.button("Scan"):
    payload = {
        "url": url,
        "method": method,
        "token": token.strip() or None,
        "body": eval(body_text) if body_text.strip() else {}
    }
    res = requests.post("http://127.0.0.1:8000/scan", json=payload)
    data = res.json()

    st.subheader("Risk Summary")
    st.write(data["scan"]["risk_level"].upper(), "score:", data["scan"]["risk_score"])

    st.subheader("Findings")
    st.json(data["scan"]["findings"])

    if data.get("jwt"):
        st.subheader("JWT Analysis")
        st.json(data["jwt"])
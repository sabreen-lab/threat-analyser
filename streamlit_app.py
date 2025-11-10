import streamlit as st
from scan_url import scan_url  # importing your existing function

st.title("Cybersecurity Threat Analyzer")

url = st.text_input("Enter a URL to scan:")

if st.button("Scan URL"):
    if url:
        st.write("Scanning, please wait...")
        result = scan_url(url)
        st.success("Scan Complete ")
        st.dataframe(result)
    else:
        st.error("Please enter a valid URL")

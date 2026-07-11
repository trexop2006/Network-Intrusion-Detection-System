import streamlit as st
import pandas as pd
import joblib
import numpy as np
from datetime import datetime
import time
model=joblib.load('random_forest_model.joblib.pkl')
protocol_encoder=joblib.load('protocol_encoder.pkl')
flag_encoder=joblib.load('flag_encoder.pkl')
service_encoder=joblib.load('service_encoder.pkl')

st.set_page_config(page_title="Intrusion Detection",page_icon=":guardsman:",layout="wide")

st.markdown("""
<style>
            
div.stButton > button {
    height: 70px;
    font-size: 20px;
    font-weight: bold;
    border-radius: 10px;
    width: 100%;
    border: 2px solid green;
}
    div.stButton > button p {
    font-size: 28px !important;
    font-weight: 700 !important;
}
</style>
""", unsafe_allow_html=True)
st.title("🛡️ Network Intrusion Detection System")
st.caption("AI Powered Network Traffic Analysis")
st.warning(
    """
⚠️ **Input Guidelines**
• Enter only valid network values.
• Negative values are not allowed.
• Rate fields must be between **0.0 and 1.0**.
• Invalid inputs may affect intrusion detection accuracy.
"""
)
st.markdown("---")
st.subheader("🛡️ Intelligent Network Traffic Analysis")

st.write(
    "Analyze network connection details and identify potential intrusion attacks using a trained Random Forest Machine Learning model."
)
if "history" not in st.session_state:
     st.session_state.history=[]
st.subheader("📥 Enter Network Connection Details")
st.info("Please ensure all values are entered correctly before detecting the intrusion.")


col1,col2=st.columns(2)

with col1:
    protocol_type=st.selectbox('Protocol (TCP / UDP / ICMP)',protocol_encoder.classes_)
    service=st.selectbox('Network Service',service_encoder.classes_)
    flag=st.selectbox('Connection Status',flag_encoder.classes_)
    duration=st.number_input('Connection Time (Seconds)',min_value=0, value=0)
    src_bytes=st.number_input('Data Sent (Bytes)',min_value=0,value=0)
    dst_bytes=st.number_input('Data Received (Bytes)',min_value=0,value=0)
    logged_in=st.selectbox('Loggin Successful',["No","Yes"])
    count=st.number_input('Recent Connections',min_value=0,value=0)
with col2:

    same_srv_rate = st.number_input(
        "Same Service Usage(0-1)",
        min_value=0.0,
        max_value=1.0,
        value=0.0,
        step=0.01
    )

    serror_rate = st.number_input(
        "Connection Error Rate(0-1)",
        min_value=0.0,
        max_value=1.0,
        value=0.0,
        step=0.01
    )

    srv_serror_rate = st.number_input(
        "Service Error Rate(0-1)",
        min_value=0.0,
        max_value=1.0,
        value=0.0,
        step=0.01
    )

    dst_host_diff_srv_rate = st.number_input(
        "Different Service Usage (0-1)",
        min_value=0.0,
        max_value=1.0,
        value=0.0,
        step=0.01
    )

    dst_host_same_src_port_rate = st.number_input(
        "Same Port Usage (0-1)",
        min_value=0.0,
        max_value=1.0,
        value=0.0,
        step=0.01
    )

    dst_host_srv_diff_host_rate = st.number_input(
        "Different Host Usage (0-1)",
        min_value=0.0,
        max_value=1.0,
        value=0.0,
        step=0.01
    )

    dst_host_srv_count = st.number_input(
        "Services Used by Destination Host",
        min_value=0,
        value=0
    )

st.markdown("---")
st.subheader("🚀 Run Intrusion Detection")
if st.button("🛡️ Detect Intrusion", use_container_width=True):
        with st.spinner("Analyzing Network Traffic...Please Wait"):
             time.sleep(3)
        

        protocol=protocol_encoder.transform([protocol_type])[0]
        service_name=service_encoder.transform([service])[0]
        flag_name=flag_encoder.transform([flag])[0]
        logged_in = 1 if logged_in == "Yes" else 0
        input_data = np.array([[
        duration,
        protocol,
        service_name,
        flag_name,
        src_bytes,
        dst_bytes,
        logged_in,
        count,
        same_srv_rate,
        serror_rate,
        srv_serror_rate,
        dst_host_diff_srv_rate,
        dst_host_same_src_port_rate,
        dst_host_srv_diff_host_rate,
        dst_host_srv_count
    ]])
        prediction=model.predict(input_data)[0]
        confidence=model.predict_proba(input_data).max()*100
        class_names={
            0:"Normal",
            1:"DoS",
            2:"R2L",
            3:"Probe",
            4:"U2R"
        }
        result=class_names[prediction]
        attack_description={
            "Normal":"No Malicious Activity detected. The network traffic appears safe.",
            "DoS":"Denial of Service Attack Detected. The attacker is trying to overwhelm the system with excessive traffic.",
            "R2L":"Remote to Local Attack Detected. The attacker is attempting to gain local access from remote location.",
            "Probe":"Probe Attack Detected. The attacker is trying to gather information about the system to identify the vulnerbilities.",
            "U2R":"User to Root Attack Detected. The attacker is trying to gain root access to the system."
        }
        attack_recommendation = {
    "Normal": "No action required. Your network traffic appears safe.",

    "DoS": "Monitor incoming traffic, enable firewall protection, and block suspicious IP addresses.",

    "Probe": "Monitor network scans, review logs, and identify the source of suspicious activity.",

    "R2L": "Review user authentication, change passwords, and check unauthorized login attempts.",

    "U2R": "Immediately review system privileges, audit user accounts, and investigate potential privilege escalation."
}
        if result=="Normal":
            risk="🟢 Low"
        elif result=="Probe":
            risk= "🟠 Medium"
        else:
            risk= "🔴 High"

        if result=="Normal":
            st.success(f"""## ✅ Network Status: Normal

**Attack Type:** None

**Risk Level:** {risk}
**Confidence:** {confidence:.2f}%

""")
        else:
            st.error(f"""## 🚨 Intrusion Detected

**Attack Type:** {result}

**Risk Level:** {risk}
**Confidence:** {confidence:.2f}%

""")

        st.info(f"""
### 📖 Attack Description

{attack_description[result]}
""")

        st.info(f"""
### 💡 Recommendation

{attack_recommendation[result]}
""")

        st.session_state.history.append({
            "Time": datetime.now().strftime("%H:%M:%S"),
            "Prediction": result,
            "Risk": risk,
            "Confidence": f"{confidence:.2f}%"
        })
st.sidebar.markdown("### 🔗 Quick Links")

st.sidebar.link_button(
    "💻 GitHub Repository",
    "https://github.com/trexop2006/Network-Intrusion-Detection-System"
)
st.sidebar.title("📌 Project Information")

st.sidebar.info("""
### 🛡️ Network Intrusion Detection System

**🤖 Model Used**
- Random Forest Classifier

**📂 Dataset**
- KDD Cup 1999

**🎯 Model Accuracy**
- 99.67%

**📊 Features Used**
- 15 Network Features

**🎓 Project Type**
- Machine Learning
- Cyber Security

**👨‍💻 Developer**
- Hardik Chaturvedi
""")
st.sidebar.info("""
...
👨‍💻 Developer
- Hardik Chaturvedi
""")

st.sidebar.markdown("---")
st.markdown("---")
st.subheader("📊 Prediction History")
st.markdown("---")

st.subheader("📊 Prediction History")

if st.session_state.history:
    st.dataframe(
        st.session_state.history,
        use_container_width=True
    )
else:
    st.info("No predictions made yet.")
st.markdown("---")
st.sidebar.success("🟢 System Ready")

st.caption("🛡️ Network Intrusion Detection System | Developed by Hardik Chaturvedi | © 2026")
    

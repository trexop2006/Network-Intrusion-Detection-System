# 🛡️ Network Intrusion Detection System

An AI-powered Network Intrusion Detection System developed using **Machine Learning** and **Streamlit**. The application analyzes network connection details and classifies network traffic as **Normal** or one of the common intrusion attack types.

---

## 🚀 Features

- Detects Normal and Intrusion traffic
- Random Forest Machine Learning model
- Real-time prediction through Streamlit interface
- Confidence Score for every prediction
- Risk Level Indicator
- Attack Description
- Security Recommendation
- Prediction History
- User-friendly interface

---

## 🎯 Attack Categories

- ✅ Normal
- 🚨 DoS (Denial of Service)
- 🔍 Probe
- 🔐 R2L (Remote to Local)
- ⚠️ U2R (User to Root)

---

## 🧠 Machine Learning Model

- Algorithm: Random Forest Classifier
- Dataset: KDD Cup 1999
- Features Used: 15
- Accuracy: 99.67%

---

## 🛠️ Technologies Used

- Python
- Streamlit
- Scikit-learn
- NumPy
- Pandas
- Joblib

---

## 📂 Project Structure

```
Network-Intrusion-Detection-System/
│
├── app.py
├── random_forest_model.joblib.pkl
├── protocol_encoder.pkl
├── service_encoder.pkl
├── flag_encoder.pkl
├── requirements.txt
└── README.md
```

---

## ▶️ Installation

Clone the repository:

```bash
git clone https://github.com/your-username/Network-Intrusion-Detection-System.git
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
streamlit run app.py
```

---

## 📊 Application Workflow

1. Enter network connection details.
2. Click **Detect Intrusion**.
3. The model analyzes the network traffic.
4. The application displays:
   - Prediction
   - Confidence Score
   - Risk Level
   - Attack Description
   - Security Recommendation

---

## ⚠️ Limitations

- Uses the KDD Cup 1999 dataset.
- Supports only the selected 15 network features.
- Does not monitor live network traffic.
- Unknown attack types may not be classified correctly.

---

## 🚀 Future Scope

- Real-time network traffic monitoring
- Deep Learning-based intrusion detection
- Email and SMS alerts
- Firewall integration
- Live packet analysis using Wireshark

---

## 👨‍💻 Developer

**Hardik Chaturvedi**

BCA Student

Machine Learning & Cyber Security Enthusiast

---

## 📄 License

This project is developed for educational purposes.

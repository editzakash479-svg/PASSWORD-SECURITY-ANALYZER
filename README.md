# Password Security Analyzer

A beginner/intermediate Python + Streamlit web application for a B.Tech 2nd-year CSE mini project.

## Features
- Password strength score and category
- Character composition checks
- Approximate entropy estimate
- Common-password sample-list detection
- Repeated-character and predictable-sequence warnings
- Security recommendations
- Secure password generator using Python `secrets`
- Project overview page

## Requirements
- Python 3.9 or later
- pip

## Run on Windows
1. Install Python from https://www.python.org/
2. Extract this ZIP file.
3. Open Command Prompt in the extracted folder.
4. Run:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Run on macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

The app opens in your browser, normally at http://localhost:8501.

## Project structure

```text
password_security_analyzer/
├── app.py
├── requirements.txt
└── README.md
```

## Important privacy note
The app does not save passwords to a file or database. For classroom demonstrations, use sample passwords rather than a real password. The strength score and entropy are educational estimates, not a professional security audit.

## Suggested mini-project explanation
The application uses Python functions to evaluate password length, character classes and simple weak patterns. A weighted heuristic produces a score from 0 to 100. Entropy is estimated from the detected character pool. The password generator uses the `secrets` module rather than the ordinary `random` module.

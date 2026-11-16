import math
import re
import secrets
import string
import streamlit as st

# Password Security Analyzer
# Educational mini-project for B.Tech CSE (2nd year).
# Passwords are analyzed in-memory only; this app does not save them.

st.set_page_config(
    page_title="Password Security Analyzer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

COMMON_PASSWORDS = {
    "password", "password123", "123456", "123456789", "12345678",
    "qwerty", "qwerty123", "abc123", "111111", "admin", "letmein",
    "welcome", "iloveyou", "india123", "admin123", "pass@123",
    "000000", "123123", "p@ssword", "changeme"
}

# ---------- Styling ----------
st.markdown("""
<style>
    .main { background: #f7f9fc; }
    .block-container { padding-top: 1.6rem; padding-bottom: 2rem; }
    .hero {
        padding: 1.35rem 1.6rem; border-radius: 16px;
        background: linear-gradient(115deg, #ffffff, #edf4ff);
        border: 1px solid #dce7f7; margin-bottom: 1rem;
    }
    .hero h1 { color: #173b70; margin: 0; font-size: 2rem; }
    .hero p { color: #53657d; margin: .35rem 0 0 0; }
    .metric-card {
        background: white; border: 1px solid #e4eaf2;
        border-radius: 13px; padding: 1rem; min-height: 105px;
    }
    .metric-label { color: #64748b; font-size: .88rem; }
    .metric-value { color: #172b4d; font-size: 1.55rem; font-weight: 700; }
    .small-note { color: #64748b; font-size: .83rem; }
    div[data-testid="stProgressBar"] > div > div { background-color: #2563eb; }
</style>
""", unsafe_allow_html=True)

# ---------- Analysis functions ----------
def estimate_entropy(password: str) -> float:
    """Approximate entropy in bits using the size of the detected character pool."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool +=  symbol_count()
    if pool <= 1 or not password:
        return 0.0
    return len(password) * math.log2(pool)


def symbol_count() -> int:
    return len(string.punctuation)


def analyze_password(password: str) -> dict:
    length = len(password)
    checks = {
        "At least 8 characters": length >= 8,
        "At least 12 characters": length >= 12,
        "Contains uppercase letter": any(c.isupper() for c in password),
        "Contains lowercase letter": any(c.islower() for c in password),
        "Contains a number": any(c.isdigit() for c in password),
        "Contains a special character": any(not c.isalnum() for c in password),
    }

    score = 0
    score += 20 if length >= 8 else (10 if length >= 6 else 0)
    score += 15 if length >= 12 else (5 if length >= 10 else 0)
    score += 15 if checks["Contains uppercase letter"] else 0
    score += 15 if checks["Contains lowercase letter"] else 0
    score += 15 if checks["Contains a number"] else 0
    score += 20 if checks["Contains a special character"] else 0

    lower = password.lower()
    warnings = []
    suggestions = []

    if not password:
        return {
            "score": 0, "strength": "Not analyzed", "checks": checks,
            "entropy": 0.0, "warnings": [], "suggestions": ["Enter a password to begin analysis."],
            "common": False
        }

    common = lower in COMMON_PASSWORDS
    if common:
        score = min(score, 15)
        warnings.append("This password appears in the application's common-password sample list.")

    if re.search(r"(.)\1{2,}", password):
        score = max(0, score - 10)
        warnings.append("Repeated characters (for example, 'aaa') make a password easier to guess.")

    if re.search(r"1234|2345|3456|4567|5678|6789|abcd|qwerty", lower):
        score = max(0, score - 10)
        warnings.append("A predictable sequence or keyboard pattern was detected.")

    if length < 8:
        suggestions.append("Use at least 12 characters; longer passphrases are usually easier to remember.")
    elif length < 12:
        suggestions.append("Increase the length to 12–16 characters or more.")

    if not checks["Contains uppercase letter"]:
        suggestions.append("Add one or more uppercase letters.")
    if not checks["Contains lowercase letter"]:
        suggestions.append("Include lowercase letters.")
    if not checks["Contains a number"]:
        suggestions.append("Include numbers, but avoid obvious sequences.")
    if not checks["Contains a special character"]:
        suggestions.append("Add a special character such as !, @, # or %.")
    if common:
        suggestions.append("Avoid common passwords and personal information.")
    if not suggestions and not warnings:
        suggestions.append("Good structure. Use a unique password for every account and enable multi-factor authentication.")

    if score >= 80:
        strength = "Very Strong"
    elif score >= 60:
        strength = "Strong"
    elif score >= 40:
        strength = "Medium"
    else:
        strength = "Weak"

    return {
        "score": min(score, 100),
        "strength": strength,
        "checks": checks,
        "entropy": estimate_entropy(password),
        "warnings": warnings,
        "suggestions": suggestions,
        "common": common,
    }


def generate_password(length: int, use_upper: bool, use_lower: bool,
                      use_digits: bool, use_symbols: bool) -> str:
    pools = []
    if use_upper: pools.append(string.ascii_uppercase)
    if use_lower: pools.append(string.ascii_lowercase)
    if use_digits: pools.append(string.digits)
    if use_symbols: pools.append(string.punctuation)
    if not pools:
        raise ValueError("Select at least one character type.")
    if length < len(pools):
        raise ValueError("Length must be at least the number of selected character types.")

    # Ensure at least one character from every selected category.
    chars = [secrets.choice(pool) for pool in pools]
    all_chars = "".join(pools)
    chars.extend(secrets.choice(all_chars) for _ in range(length - len(chars)))
    # secrets.SystemRandom is suitable for security-sensitive randomization.
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ---------- Sidebar ----------
with st.sidebar:
    st.title("🔐 Password Analyzer")
    st.caption("B.Tech CSE Mini Project")
    page = st.radio("Navigation", ["Password Analyzer", "Password Generator", "About Project"])
    st.divider()
    st.markdown("**Project details**")
    st.caption("Python • Streamlit • Cyber Security")
    st.caption("Educational demonstration")

# ---------- Header ----------
st.markdown("""
<div class="hero">
  <h1>🔐 Password Security Analyzer</h1>
  <p>Evaluate password strength, understand security risks, and create stronger passwords.</p>
</div>
""", unsafe_allow_html=True)

if page == "Password Analyzer":
    st.subheader("Analyze your password")
    st.info("Privacy: your password is processed in this running app only. It is not saved to a file or database. Avoid entering a password you currently use for an important account in a demonstration.")

    with st.form("analyze_form", clear_on_submit=False):
        password = st.text_input("Enter a password", type="password", placeholder="Type a sample password...")
        show_password = st.checkbox("Show password while typing")
        submitted = st.form_submit_button("Analyze Password", type="primary", use_container_width=True)

    # The show/hide checkbox is intentionally informational: Streamlit's password
    # input remains masked to avoid exposing credentials on a shared screen.
    if show_password:
        st.caption("For privacy, the password field remains masked in this demo.")

    if submitted:
        result = analyze_password(password)
        st.session_state["last_result"] = result
        st.session_state["analyzed"] = bool(password)

    if st.session_state.get("analyzed", False):
        result = st.session_state["last_result"]
        st.divider()
        st.subheader("Analysis dashboard")

        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f'<div class="metric-card"><div class="metric-label">Strength level</div><div class="metric-value">{result["strength"]}</div></div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="metric-card"><div class="metric-label">Security score</div><div class="metric-value">{result["score"]}/100</div></div>', unsafe_allow_html=True)
        with col3:
            st.markdown(f'<div class="metric-card"><div class="metric-label">Estimated entropy</div><div class="metric-value">{result["entropy"]:.1f} bits</div></div>', unsafe_allow_html=True)

        st.write("")
        st.progress(result["score"] / 100, text=f"Password score: {result['score']} out of 100")

        left, right = st.columns(2)
        with left:
            st.markdown("#### Security requirements")
            for label, passed in result["checks"].items():
                st.write(("✅ " if passed else "❌ ") + label)
        with right:
            st.markdown("#### Recommendations")
            for item in result["suggestions"]:
                st.write("• " + item)

        if result["warnings"]:
            st.markdown("#### ⚠️ Security warnings")
            for warning in result["warnings"]:
                st.warning(warning)
        elif result["score"] >= 60:
            st.success("No obvious weak patterns were detected by this basic analyzer.")

        st.caption("Note: this is an educational heuristic, not a guarantee that a password is safe. Entropy is an estimate and does not measure real-world guessability perfectly.")

elif page == "Password Generator":
    st.subheader("Generate a secure password")
    st.write("Choose the password length and character types. The generator uses Python's `secrets` module.")
    with st.form("generator_form"):
        length = st.slider("Password length", min_value=8, max_value=32, value=16)
        c1, c2 = st.columns(2)
        with c1:
            upper = st.checkbox("Uppercase letters (A–Z)", value=True)
            lower = st.checkbox("Lowercase letters (a–z)", value=True)
        with c2:
            digits = st.checkbox("Numbers (0–9)", value=True)
            symbols = st.checkbox("Special characters (!@#...)", value=True)
        generate = st.form_submit_button("Generate Password", type="primary", use_container_width=True)

    if generate:
        try:
            generated = generate_password(length, upper, lower, digits, symbols)
            st.session_state["generated_password"] = generated
        except ValueError as error:
            st.error(str(error))

    if st.session_state.get("generated_password"):
        st.success("Password generated successfully.")
        st.code(st.session_state["generated_password"], language=None)
        st.caption("Copy it to a trusted password manager. Do not reuse it across websites.")
        if st.button("Clear generated password"):
            st.session_state.pop("generated_password", None)
            st.rerun()

elif page == "About Project":
    st.subheader("About the mini project")
    st.markdown("""
    **Project title:** Password Security Analyzer

    **Objective:** To develop a simple web-based tool that evaluates password composition,
    identifies common weak patterns, estimates theoretical entropy, and provides improvement
    suggestions.

    **Technologies used**
    - Python 3
    - Streamlit for the web interface
    - Regular expressions for pattern detection
    - `math` for entropy estimation
    - `secrets` for secure random password generation

    **How it works**
    1. The user enters a sample password.
    2. The application checks length and character categories.
    3. It checks a small built-in list of common passwords and a few predictable patterns.
    4. A heuristic score and entropy estimate are calculated.
    5. The dashboard displays the result and suggestions.

    **Limitations:** The common-password list is intentionally small for a student demonstration.
    This application does not check leaked-password databases, does not perform a full password
    audit, and does not guarantee protection against every attack.
    """)
    st.warning("Use this project for learning and demonstration. Never collect or store other people's passwords.")

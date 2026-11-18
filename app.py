
import streamlit as st
import matplotlib.pyplot as plt
from datetime import datetime
from pathlib import Path

st.set_page_config(page_title="LogLens", page_icon="🔐")

st.title("🔐 LOGLENS")
st.subheader("Security Log Analysis System")
st.write("Upload your security log file to detect suspicious activity.")

uploaded_file = st.file_uploader("Upload Log File", type=["txt", "log"])

if uploaded_file is not None:
    logs = uploaded_file.getvalue().decode("utf-8", errors="ignore").splitlines()

    successful = sum("Login Successful" in x for x in logs)
    failed = sum("Login Failed" in x for x in logs)

    failed_ips = {}
    patterns = {
        "SQL Injection": ["' OR 1=1", "UNION SELECT"],
        "XSS": ["<script>", "javascript:"],
        "Directory Traversal": ["../", "../../etc/passwd"]
    }

    attacks = []

    for log in logs:
        if "Login Failed" in log:
            ip = log.split(" - ")[0]
            failed_ips[ip] = failed_ips.get(ip, 0) + 1

        for name, signatures in patterns.items():
            if any(p.lower() in log.lower() for p in signatures):
                severity = "HIGH" if name in ["SQL Injection", "XSS"] else "MEDIUM"
                attacks.append((name, severity, log))
                break

    suspicious = [ip for ip, count in failed_ips.items() if count >= 3]

    st.header("Security Summary")
    st.metric("Total Logs", len(logs))
    st.metric("Successful Logins", successful)
    st.metric("Failed Logins", failed)
    st.write("Suspicious IPs:", suspicious if suspicious else "None")

    st.header("Detected Attacks")
    if attacks:
        for name, severity, log in attacks:
            st.warning(f"{name} | {severity}\n\n{log}")
    else:
        st.success("No attacks detected")

    fig, ax = plt.subplots()
    ax.bar(["Successful", "Failed"], [successful, failed])
    ax.set_title("Login Activity")
    st.pyplot(fig)

    report = "LOGLENS SECURITY REPORT\n"
    report += "Generated: " + str(datetime.now()) + "\n"
    report += f"Total Logs: {len(logs)}\n"
    report += f"Successful Logins: {successful}\n"
    report += f"Failed Logins: {failed}\n"
    report += f"Suspicious IPs: {suspicious}\n\n"
    report += "DETECTED ATTACKS:\n"
    report += "\n".join(f"{a} | {s} | {l}" for a, s, l in attacks)

    st.download_button(
        "Download Security Report",
        report,
        file_name="LogLens_Report.txt"
    )

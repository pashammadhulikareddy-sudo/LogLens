
import streamlit as st
import matplotlib.pyplot as plt
from datetime import datetime
import re
import requests
import ipaddress

st.set_page_config(page_title="LogLens", page_icon="🔐", layout="wide")


def get_ip_location(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)

        if not ip_obj.is_global:
            return "Private IP - Location not available"

        response = requests.get(
            f"https://ipwho.is/{ip}",
            timeout=5
        )

        data = response.json()

        if data.get("success"):
            return (
                f"Country: {data.get('country', 'Unknown')} | "
                f"City: {data.get('city', 'Unknown')} | "
                f"Region: {data.get('region', 'Unknown')}"
            )

        return "Location not available"

    except Exception:
        return "GeoIP lookup failed"


st.title("🔐 LOGLENS")
st.subheader("Security Log Analysis Dashboard")
st.write("Upload Apache, Nginx or sample security logs.")

uploaded_file = st.file_uploader("Upload Log File", type=["txt", "log"])

if uploaded_file:
    total_logs = 0

    successful = 0
    failed = 0
    failed_ips = {}
    status_codes = {}

    patterns = {
        "SQL Injection": ["' OR 1=1", "UNION SELECT"],
        "XSS": ["<script>", "javascript:"],
        "Directory Traversal": ["../", "../../etc/passwd"]
    }

    attacks = []
    attack_times = []

    for log in logs:
        match = re.search(r'"[^"]+"\s+(\d{3})', log)

        if match:
            status = match.group(1)
            status_codes[status] = status_codes.get(status, 0) + 1

            if status.startswith("2"):
                successful += 1

            elif status.startswith(("4", "5")):
                failed += 1
                ip = log.split()[0]
                failed_ips[ip] = failed_ips.get(ip, 0) + 1

        for name, signatures in patterns.items():
            if any(p.lower() in log.lower() for p in signatures):
                severity = (
                    "HIGH"
                    if name in ["SQL Injection", "XSS"]
                    else "MEDIUM"
                )

                attacks.append((name, severity, log))

                time_match = re.search(r'\[(.*?)\]', log)

                if time_match:
                    try:
                        attack_time = datetime.strptime(
                            time_match.group(1),
                            "%d/%b/%Y:%H:%M:%S %z"
                        )

                        attack_times.append(
                            attack_time.strftime("%Y-%m-%d %H:00")
                        )

                    except ValueError:
                        pass

                break

    suspicious = [
        ip for ip, count in failed_ips.items() if count >= 3
    ]

    high = sum(1 for a in attacks if a[1] == "HIGH")
    medium = sum(1 for a in attacks if a[1] == "MEDIUM")

    st.header("Security Overview")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Logs", len(logs))
    c2.metric("Successful Requests", successful)
    c3.metric("Failed Requests", failed)
    c4.metric("Detected Attacks", len(attacks))

    st.subheader("Attack Severity")

    c5, c6 = st.columns(2)

    c5.metric("HIGH Severity", high)
    c6.metric("MEDIUM Severity", medium)

    st.subheader("Detected Attacks")

    if attacks:
        for name, severity, log in attacks:
            if severity == "HIGH":
                st.error(f"{name} | {severity}\n\n{log}")
            else:
                st.warning(f"{name} | {severity}\n\n{log}")
    else:
        st.success("No attacks detected")

    st.subheader("Attacks Per Hour")

    if attack_times:
        time_counts = {}

        for t in attack_times:
            time_counts[t] = time_counts.get(t, 0) + 1

        times = sorted(time_counts.keys())
        counts = [time_counts[t] for t in times]

        fig, ax = plt.subplots()

        ax.bar(times, counts)
        ax.set_title("Cyber Attacks Per Hour")
        ax.set_xlabel("Time")
        ax.set_ylabel("Number of Attacks")
        ax.tick_params(axis="x", rotation=45)

        st.pyplot(fig)
    else:
        st.info("No timestamped attacks found")

    st.subheader("Security Charts")

    col1, col2 = st.columns(2)

    with col1:
        fig, ax = plt.subplots()

        ax.bar(
            ["Successful", "Failed"],
            [successful, failed],
            color=["#2ecc71", "#e74c3c"]
        )

        ax.set_title("Request Status")
        ax.set_ylabel("Number of Requests")

        st.pyplot(fig)

    with col2:
        fig, ax = plt.subplots()

        ax.bar(
            ["SQL Injection", "XSS", "Directory Traversal"],
            [
                sum(1 for a in attacks if a[0] == "SQL Injection"),
                sum(1 for a in attacks if a[0] == "XSS"),
                sum(1 for a in attacks if a[0] == "Directory Traversal")
            ],
            color=["#e74c3c", "#9b59b6", "#f39c12"]
        )

        ax.set_title("Detected Attack Types")
        ax.set_ylabel("Number of Attacks")
        ax.tick_params(axis="x", rotation=15)

        st.pyplot(fig)

    st.subheader("HTTP Status Codes")
    st.write(status_codes if status_codes else "No HTTP status codes found")

    st.subheader("Suspicious IP Addresses")
    st.write(suspicious if suspicious else "None")

    if suspicious:
        for ip in suspicious:
            st.error(f"Possible Brute Force Attack from IP: {ip}")

    st.subheader("🌍 GeoIP - Attacker Location")

    attacker_ips = list(dict.fromkeys(
        [log.split()[0] for name, severity, log in attacks]
        + suspicious
    ))

    if attacker_ips:
        for ip in attacker_ips:
            st.write(f"**IP Address:** {ip}")
            location = get_ip_location(ip)
            st.write(f"**Location:** {location}")
            st.divider()
    else:
        st.info("No attacker IP addresses found")

    report = f"""LOGLENS SECURITY REPORT
Generated: {datetime.now()}
Total Logs: {len(logs)}
Successful Requests: {successful}
Failed Requests: {failed}
Detected Attacks: {len(attacks)}
HIGH Severity: {high}
MEDIUM Severity: {medium}
HTTP Status Codes: {status_codes}
Suspicious IPs: {suspicious}

DETECTED ATTACKS:
"""

    report += "\n".join(
        f"{a} | {s} | {log}" for a, s, log in attacks
    )

    st.download_button(
        "Download Security Report",
        report,
        file_name="LogLens_Report.txt"
    )

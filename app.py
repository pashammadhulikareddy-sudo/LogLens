import streamlit as st
import matplotlib.pyplot as plt
from datetime import datetime
import re
import requests
import ipaddress
import time

st.set_page_config(
    page_title="LogLens",
    page_icon="🔐",
    layout="wide"
)

st.markdown("""
<style>
.stApp {
    background-color: #0e1117;
    color: #ffffff;
}

[data-testid="stMetric"] {
    background-color: #1c2333;
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #303b50;
}

h1, h2, h3 {
    color: #00d4ff;
}

.stButton button {
    background-color: #0077b6;
    color: white;
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)

[data-testid="stMetric"] {
    background-color: #1c2333;
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #303b50;
}

h1, h2, h3 {
    color: #00d4ff;
}

.stButton button {
    background-color: #0077b6;
    color: white;
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)
    page_title="LogLens",
    page_icon="🔐",
    layout="wide"
)


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

uploaded_file = st.file_uploader(
    "Upload Log File",
    type=["txt", "log"]
)

if uploaded_file:
    start_time = time.time()
    successful = 0
    failed = 0
    total_logs = 0

    failed_ips = {}
    status_codes = {}

    patterns = {
        "SQL Injection": ["' OR 1=1", "UNION SELECT"],
        "XSS": ["<script>", "javascript:"],
        "Directory Traversal": [
            "../",
            "../../etc/passwd"
        ]
    }

    attacks = []
    attack_times = []

    # Process logs one line at a time
    uploaded_file.seek(0)

    progress_text = st.empty()
    progress_bar = st.progress(0)

    file_size = uploaded_file.size

    for raw_line in uploaded_file:

        log = raw_line.decode(
            "utf-8",
            errors="ignore"
        ).strip()

        if not log:
            continue

        total_logs += 1

        # HTTP status code analysis
        match = re.search(
            r'"[^"]+"\s+(\d{3})',
            log
        )

        if match:
            status = match.group(1)

            status_codes[status] = (
                status_codes.get(status, 0) + 1
            )

            if status.startswith("2"):
                successful += 1

            elif status.startswith(("4", "5")):
                failed += 1

                ip = log.split()[0]

                failed_ips[ip] = (
                    failed_ips.get(ip, 0) + 1
                )

        # Attack detection
        for name, signatures in patterns.items():

            if any(
                pattern.lower() in log.lower()
                for pattern in signatures
            ):

                severity = (
                    "HIGH"
                    if name in ["SQL Injection", "XSS"]
                    else "MEDIUM"
                )

                attacks.append(
                    (name, severity, log)
                )

                time_match = re.search(
                    r'\[(.*?)\]',
                    log
                )

                if time_match:
                    try:
                        attack_time = datetime.strptime(
                            time_match.group(1),
                            "%d/%b/%Y:%H:%M:%S %z"
                        )

                        attack_times.append(
                            attack_time.strftime(
                                "%Y-%m-%d %H:00"
                            )
                        )

                    except ValueError:
                        pass

                break

        # Update progress
        if file_size > 0:
            progress = min(
                uploaded_file.tell() / file_size,
                1.0
            )

            progress_bar.progress(progress)
    end_time = time.time()
    processing_time = end_time - start_time
    progress_text.success(
        "Log file processing completed!"
    )

    progress_bar.empty()

    # Brute force detection
    suspicious = [
        ip for ip, count in failed_ips.items()
        if count >= 3
    ]

    high = sum(
        1 for attack in attacks
        if attack[1] == "HIGH"
    )

    medium = sum(
        1 for attack in attacks
        if attack[1] == "MEDIUM"
    )

    # Security overview
    st.header("Security Overview")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Logs", total_logs)
    c2.metric("Successful Requests", successful)
    c3.metric("Failed Requests", failed)
    c4.metric("Detected Attacks", len(attacks))
    st.subheader("⚡ Performance Analysis")

    col5, col6 = st.columns(2)

    col5.metric(
        "Processing Time",
        f"{processing_time:.4f} seconds"
    )

    logs_per_second = (
        total_logs / processing_time
        if processing_time > 0
        else 0
    )

    col6.metric(
        "Logs Processed Per Second",
        f"{logs_per_second:.2f}"
    )
    st.subheader("Attack Severity")

    c5, c6 = st.columns(2)

    c5.metric("HIGH Severity", high)
    c6.metric("MEDIUM Severity", medium)

    # Detected attacks
    st.subheader("Detected Attacks")

    if attacks:
        for name, severity, log in attacks:

            if severity == "HIGH":
                st.error(
                    f"{name} | {severity}\n\n{log}"
                )
            else:
                st.warning(
                    f"{name} | {severity}\n\n{log}"
                )
    else:
        st.success("No attacks detected")

    # Attacks per hour
    st.subheader("Attacks Per Hour")

    if attack_times:

        time_counts = {}

        for time in attack_times:
            time_counts[time] = (
                time_counts.get(time, 0) + 1
            )

        times = sorted(time_counts.keys())

        counts = [
            time_counts[time]
            for time in times
        ]

        fig, ax = plt.subplots()

        ax.bar(times, counts)

        ax.set_title("Cyber Attacks Per Hour")
        ax.set_xlabel("Time")
        ax.set_ylabel("Number of Attacks")

        ax.tick_params(
            axis="x",
            rotation=45
        )

        st.pyplot(fig)
        plt.close(fig)

    else:
        st.info("No timestamped attacks found")

    # Security charts
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
        plt.close(fig)

    with col2:

        fig, ax = plt.subplots()

        ax.bar(
            [
                "SQL Injection",
                "XSS",
                "Directory Traversal"
            ],
            [
                sum(
                    1 for a in attacks
                    if a[0] == "SQL Injection"
                ),
                sum(
                    1 for a in attacks
                    if a[0] == "XSS"
                ),
                sum(
                    1 for a in attacks
                    if a[0] == "Directory Traversal"
                )
            ],
            color=[
                "#e74c3c",
                "#9b59b6",
                "#f39c12"
            ]
        )

        ax.set_title("Detected Attack Types")
        ax.set_ylabel("Number of Attacks")

        ax.tick_params(
            axis="x",
            rotation=15
        )

        st.pyplot(fig)
        plt.close(fig)

    # HTTP status codes
    st.subheader("HTTP Status Codes")

    st.write(
        status_codes
        if status_codes
        else "No HTTP status codes found"
    )

    # Suspicious IP addresses
    st.subheader("Suspicious IP Addresses")

    st.write(
        suspicious
        if suspicious
        else "None"
    )

    if suspicious:
        for ip in suspicious:
            st.error(
                f"Possible Brute Force Attack from IP: {ip}"
            )

    # GeoIP
    st.subheader("🌍 GeoIP - Attacker Location")

    attacker_ips = list(dict.fromkeys(
        [
            log.split()[0]
            for name, severity, log in attacks
        ] + suspicious
    ))

    if attacker_ips:

        for ip in attacker_ips:

            st.write(f"**IP Address:** {ip}")

            location = get_ip_location(ip)

            st.write(f"**Location:** {location}")

            st.divider()

    else:
        st.info("No attacker IP addresses found")

    # Downloadable report
    report = f"""LOGLENS SECURITY REPORT

Generated: {datetime.now()}

Total Logs: {total_logs}
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
        f"{name} | {severity} | {log}"
        for name, severity, log in attacks
    )

    st.download_button(
        "Download Security Report",
        report,
        file_name="LogLens_Report.txt"
    )

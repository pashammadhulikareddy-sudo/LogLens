
import gradio as gr
import matplotlib.pyplot as plt
from datetime import datetime
from pathlib import Path

def analyze_logs(file_path):
    if not file_path:
        return "Please upload a log file.", None, None

    logs = Path(file_path).read_text(
        encoding="utf-8", errors="ignore"
    ).splitlines()

    successful = 0
    failed = 0
    failed_ips = {}

    patterns = {
        "SQL Injection": ["' OR 1=1", "UNION SELECT"],
        "XSS": ["<script>", "javascript:"],
        "Directory Traversal": ["../", "../../etc/passwd"]
    }

    attacks = []

    for log in logs:
        if "Login Successful" in log:
            successful += 1

        if "Login Failed" in log:
            failed += 1
            ip = log.split(" - ")[0]
            failed_ips[ip] = failed_ips.get(ip, 0) + 1

        for attack, signatures in patterns.items():
            if any(p.lower() in log.lower() for p in signatures):
                severity = (
                    "HIGH" if attack in ["SQL Injection", "XSS"]
                    else "MEDIUM"
                )
                attacks.append((attack, severity, log))
                break

    suspicious = [
        ip for ip, count in failed_ips.items() if count >= 3
    ]

    attack_text = "\n".join(
        f"{name} | {severity} | {log}"
        for name, severity, log in attacks
    )

    summary = f"""
LOGLENS SECURITY REPORT

Total Logs: {len(logs)}
Successful Logins: {successful}
Failed Logins: {failed}
Suspicious IPs: {suspicious}

DETECTED ATTACKS:
{attack_text if attack_text else "No attacks detected"}
"""

    fig, axes = plt.subplots(1, 2, figsize=(10, 4))

    axes[0].bar(
        ["Successful", "Failed"],
        [successful, failed]
    )
    axes[0].set_title("Login Activity")

    names = list(patterns.keys())
    counts = [
        sum(1 for a in attacks if a[0] == name)
        for name in names
    ]

    axes[1].bar(names, counts)
    axes[1].set_title("Detected Attacks")
    axes[1].tick_params(axis="x", rotation=20)

    plt.tight_layout()

    report_path = str(Path.cwd() / "LogLens_Report.txt")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("Generated: " + str(datetime.now()) + "\n")
        f.write(summary)

    return summary, fig, report_path


app = gr.Interface(
    fn=analyze_logs,
    inputs=gr.File(
        label="Upload Security Log File",
        type="filepath"
    ),
    outputs=[
        gr.Textbox(label="Security Analysis", lines=15),
        gr.Plot(label="Security Dashboard"),
        gr.File(label="Download Security Report")
    ],
    title="LOGLENS - Security Log Analyzer",
    description="Upload logs to analyze login activity and common web attack patterns."
)

if __name__ == "__main__":
    app.launch()


# report_generator.py - Enhanced Vulnerability Reporting, Compliance Mapping, and Baseline Tracking for API Security Tool

import json
import os
import matplotlib.pyplot as plt

# Define scoring criteria, compliance mappings, and MITRE ATT&CK mappings
SEVERITY_SCORES = {
    "critical": 10,
    "high": 7,
    "medium": 5,
    "low": 2,
}
COMPLIANCE_MAPPING = {
    "auth_validation": "OWASP API1: Broken Object Level Authorization",
    "rate_limiting": "OWASP API4: Lack of Resources & Rate Limiting",
    "sensitive_data_exposure": "OWASP API3: Excessive Data Exposure",
    "endpoint_enumeration": "OWASP API9: Improper Assets Management",
    "sql_injection_test": "CWE-89: SQL Injection",
    "command_injection_test": "CWE-78: Command Injection"
}
MITRE_ATTACK_MAPPING = {
    "auth_validation": "T1078: Valid Accounts",
    "rate_limiting": "T1499: Endpoint Denial of Service",
    "sensitive_data_exposure": "T1552: Data Leak Prevention",
    "endpoint_enumeration": "T1071: Application Layer Protocol",
    "sql_injection_test": "T1190: Exploitation of Vulnerability",
    "command_injection_test": "T1059: Command and Scripting Interpreter"
}

# Calculate risk score based on severity and exploitability
def calculate_risk_score(vulnerabilities):
    total_score = 0
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "low")
        exploitability = vuln.get("exploitability", 1)
        score = SEVERITY_SCORES.get(severity, 2) * exploitability
        vuln["risk_score"] = score
        vuln["compliance_mapping"] = COMPLIANCE_MAPPING.get(vuln.get("type"), "Unknown")
        vuln["mitre_attack_mapping"] = MITRE_ATTACK_MAPPING.get(vuln.get("type"), "Unknown")
        total_score += score
    return total_score

# Generate report with risk scores, compliance mappings, and remediation guidance
def generate_report(vulnerabilities, output_format="text"):
    report_data = {
        "total_vulnerabilities": len(vulnerabilities),
        "total_risk_score": calculate_risk_score(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }
    
    if output_format == "text":
        with open("api_security_report.txt", "w") as report_file:
            report_file.write("API Security Report\n")
            report_file.write("====================\n")
            report_file.write(f"Total Vulnerabilities: {report_data['total_vulnerabilities']}\n")
            report_file.write(f"Total Risk Score: {report_data['total_risk_score']}\n\n")
            
            for vuln in vulnerabilities:
                report_file.write(f"Description: {vuln['description']}\n")
                report_file.write(f"Severity: {vuln['severity']}\n")
                report_file.write(f"Risk Score: {vuln['risk_score']}\n")
                report_file.write(f"Compliance: {vuln['compliance_mapping']}\n")
                report_file.write(f"MITRE ATT&CK Mapping: {vuln['mitre_attack_mapping']}\n")
                report_file.write(f"Recommendation: {vuln['remediation']}\n\n")
    
    elif output_format == "json":
        with open("api_security_report.json", "w") as report_file:
            json.dump(report_data, report_file, indent=4)

# Baseline Tracking - Archive previous reports for comparison
def archive_report():
    if not os.path.exists("report_history"):
        os.makedirs("report_history")
    os.rename("api_security_report.txt", f"report_history/api_security_report_{len(os.listdir('report_history'))}.txt")

# Visualize Risk Scores Over Time
def visualize_risk_trend():
    scores = []
    for file in os.listdir("report_history"):
        with open(f"report_history/{file}", "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith("Total Risk Score:"):
                    scores.append(int(line.split(":")[1].strip()))

    plt.plot(scores, marker='o')
    plt.title("Risk Score Trend Over Time")
    plt.xlabel("Report History")
    plt.ylabel("Total Risk Score")
    plt.savefig("risk_trend.png")
    plt.show()

# Example vulnerability data for testing
vulnerabilities = [
    {
        "description": "Unauthorized access allowed on API endpoint.",
        "severity": "high",
        "exploitability": 3,
        "type": "auth_validation",
        "remediation": "Implement stricter authorization checks for sensitive resources."
    },
    {
        "description": "Sensitive data exposed in API response.",
        "severity": "critical",
        "exploitability": 2,
        "type": "sensitive_data_exposure",
        "remediation": "Redact sensitive fields from API responses to unauthorized users."
    }
]

# Generate example report and visualize trend
if __name__ == "__main__":
    generate_report(vulnerabilities, output_format="text")
    archive_report()  # Archive the report for baseline tracking
    visualize_risk_trend()  # Display trend over historical reports

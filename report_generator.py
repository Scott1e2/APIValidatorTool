
# report_generator.py - Enhanced Vulnerability Reporting and Baseline Tracking for API Security Tool

import json
import os

# Define scoring criteria and compliance mappings
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
    "endpoint_enumeration": "OWASP API9: Improper Assets Management"
}

# Calculate risk score based on severity
def calculate_risk_score(vulnerabilities):
    total_score = 0
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "low")
        exploitability = vuln.get("exploitability", 1)
        score = SEVERITY_SCORES.get(severity, 2) * exploitability
        vuln["risk_score"] = score
        vuln["compliance_mapping"] = COMPLIANCE_MAPPING.get(vuln.get("type"), "Unknown")
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
                report_file.write(f"Recommendation: {vuln['remediation']}\n\n")
    
    elif output_format == "json":
        with open("api_security_report.json", "w") as report_file:
            json.dump(report_data, report_file, indent=4)

# Baseline Tracking - Archive previous reports for comparison
def archive_report():
    if not os.path.exists("report_history"):
        os.makedirs("report_history")
    os.rename("api_security_report.txt", f"report_history/api_security_report_{len(os.listdir('report_history'))}.txt")

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

# Generate example report
if __name__ == "__main__":
    generate_report(vulnerabilities, output_format="text")
    archive_report()  # Archive the report for baseline tracking

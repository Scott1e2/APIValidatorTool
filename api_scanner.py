
# api_scanner.py - Core Scanning Script for API Security Testing Tool

import json
import requests

# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# Authentication Validation
def validate_auth(endpoint):
    headers = {
        "Authorization": f"{config['authentication']['token_type']} {config['authentication']['access_token']}"
    }
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 401 or response.status_code == 403:
        print(f"[WARNING] Unauthorized access on endpoint {endpoint}.")
    else:
        print(f"[INFO] Authorized access on endpoint {endpoint}.")

# Rate Limiting Check
def check_rate_limiting(endpoint):
    headers = {
        "Authorization": f"{config['authentication']['token_type']} {config['authentication']['access_token']}"
    }
    # Sending multiple requests to test rate limiting
    for i in range(5):
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 429:
            print(f"[INFO] Rate limit enforced on {endpoint} after {i+1} requests.")
            return
    print(f"[WARNING] No rate limiting detected on {endpoint}.")

# Sensitive Data Exposure Check
def check_sensitive_data(endpoint):
    headers = {
        "Authorization": f"{config['authentication']['token_type']} {config['authentication']['access_token']}"
    }
    response = requests.get(endpoint, headers=headers)
    sensitive_data_keywords = ["password", "ssn", "credit_card"]
    if any(keyword in response.text for keyword in sensitive_data_keywords):
        print(f"[ALERT] Sensitive data found in response from {endpoint}.")
    else:
        print(f"[INFO] No sensitive data detected in {endpoint} response.")

# Endpoint Enumeration
def enumerate_endpoints():
    base_url = config["api_endpoints"][0].rsplit("/", 1)[0]  # Derive base URL
    potential_endpoints = [f"{base_url}/admin", f"{base_url}/settings", f"{base_url}/config"]
    for endpoint in potential_endpoints:
        response = requests.get(endpoint)
        if response.status_code == 200:
            print(f"[INFO] Accessible endpoint found: {endpoint}")
        else:
            print(f"[INFO] Endpoint {endpoint} not accessible (Status Code: {response.status_code}).")

# Run all security scans
def run_api_security_scans():
    for endpoint in config["api_endpoints"]:
        print(f"[INFO] Starting scan for {endpoint}")
        if config["security_checks"]["auth_validation"]:
            validate_auth(endpoint)
        if config["security_checks"]["rate_limiting_check"]:
            check_rate_limiting(endpoint)
        if config["security_checks"]["sensitive_data_check"]:
            check_sensitive_data(endpoint)

    if config["security_checks"]["endpoint_enumeration"]:
        enumerate_endpoints()

if __name__ == "__main__":
    print("[INFO] Starting API security scans...")
    run_api_security_scans()

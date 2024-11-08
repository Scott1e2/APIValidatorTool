
# api_scanner.py - Enhanced Scanning Script for API Security Testing Tool

import json
import requests
import time

# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# Authentication Validation with Token Rotation and Role-Based Testing
def validate_auth(endpoint):
    roles = config['authentication'].get('role_based_testing', [])
    for role in roles:
        # Simulate access for different roles by rotating token if needed
        token = config['authentication']['access_token']  # Placeholder; could be rotated per role if needed
        headers = {"Authorization": f"{config['authentication']['token_type']} {token}"}
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 401 or response.status_code == 403:
            print(f"[WARNING] Unauthorized access for {role} on endpoint {endpoint}.")
        else:
            print(f"[INFO] Authorized access for {role} on endpoint {endpoint}.")

# Rate Limiting Check with Bypass Attempts
def check_rate_limiting(endpoint):
    headers = {
        "Authorization": f"{config['authentication']['token_type']} {config['authentication']['access_token']}"
    }
    bypassed = False
    for i in range(10):
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 429:
            print(f"[INFO] Rate limit enforced on {endpoint} after {i+1} requests.")
            break
        elif config["red_team_options"]["rate_limit_bypass"]:
            headers["User-Agent"] = f"BypassAgent-{i}"  # Simulate different user agents
            bypassed = True
    if bypassed:
        print(f"[WARNING] Rate limit bypass attempt was successful on {endpoint}.")

# Sensitive Data Exposure Check with Data Minimization
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
    
    if config["sensitive_data_handling"]["data_minimization_check"]:
        print(f"[INFO] Checking if data returned in {endpoint} meets data minimization requirements.")

# SQL Injection and Command Injection Testing
def test_injections(endpoint):
    payloads = ["' OR '1'='1", "; ls", "|| ping -c 1 127.0.0.1"]
    for payload in payloads:
        response = requests.get(endpoint, params={"input": payload})
        if response.status_code == 200 and "error" not in response.text.lower():
            print(f"[ALERT] Possible injection vulnerability on {endpoint} with payload: {payload}")

# Endpoint Enumeration with Enhanced Discovery
def enumerate_endpoints():
    base_url = config["api_endpoints"][0].rsplit("/", 1)[0]
    potential_endpoints = [f"{base_url}/admin", f"{base_url}/settings", f"{base_url}/config"]
    for endpoint in potential_endpoints:
        response = requests.get(endpoint)
        if response.status_code == 200:
            print(f"[INFO] Accessible endpoint found: {endpoint}")
        else:
            print(f"[INFO] Endpoint {endpoint} not accessible (Status Code: {response.status_code}).")

# Run all enhanced security scans
def run_api_security_scans():
    for endpoint in config["api_endpoints"]:
        print(f"[INFO] Starting enhanced scan for {endpoint}")
        if config["security_checks"]["auth_validation"]:
            validate_auth(endpoint)
        if config["security_checks"]["rate_limiting_check"]:
            check_rate_limiting(endpoint)
        if config["security_checks"]["sensitive_data_check"]:
            check_sensitive_data(endpoint)
        if config["security_checks"]["sql_injection_test"]:
            test_injections(endpoint)

    if config["security_checks"]["endpoint_enumeration"]:
        enumerate_endpoints()

if __name__ == "__main__":
    print("[INFO] Starting enhanced API security scans...")
    run_api_security_scans()

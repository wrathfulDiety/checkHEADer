import subprocess
import sys
import importlib
from datetime import datetime
import re
import time
import threading
import os


# Function to ensure required modules are installed automatically
def install_modules(modules):
    def show_loading():
        animation = ['|', '/', '-', '\\']
        idx = 0
        while install_in_progress:
            print(f"\rPlease wait, installing dependencies... {animation[idx]}", end="")
            idx = (idx + 1) % len(animation)
            time.sleep(0.1)

    global install_in_progress
    install_in_progress = True
    loading_thread = threading.Thread(target=show_loading)
    loading_thread.daemon = True
    loading_thread.start()

    for module in modules:
        try:
            importlib.import_module(module)
            print(f"[INFO] Module '{module}' is already installed.")
        except ImportError:
            print(f"[INFO] Module '{module}' not found. Installing...", end="")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", module], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f" [SUCCESS] Module '{module}' installed.")
            except subprocess.CalledProcessError as e:
                print(f" [ERROR] Failed to install module '{module}': {e}")
            time.sleep(1)

    install_in_progress = False
    loading_thread.join()


# Function to sanitize the domain name and make it suitable for a file name
def sanitize_domain(domain):
    return re.sub(r'[^a-zA-Z0-9-_]', '_', domain)


# Color logic for different status types
def get_header_color(status):
    from termcolor import colored  # Import termcolor within this function to avoid issues
    if status == "Found":
        return colored(status, "green")
    elif "Warning" in status:
        return colored(status, "yellow")
    elif status == "Missing":
        return colored(status, "red")
    return colored(status, "white")


# Function to check security headers and misconfigurations
def check_headers(target, log_filename):
    print(f"\nChecking headers for {target}")
    try:
        import requests
        from tabulate import tabulate

        response = requests.get(target, timeout=15)
        headers = response.headers

        # Updated security headers list with additional headers
        security_headers = {
            "Content-Security-Policy": "Specifies the content types and sources allowed to load on the page.",
            "X-XSS-Protection": "Enables the cross-site scripting (XSS) filter in the browser.",
            "X-Content-Type-Options": "Prevents the browser from interpreting files as a different MIME type.",
            "Strict-Transport-Security": "Enforces the use of HTTPS and prevents SSL stripping attacks.",
            "Cache-Control": "Controls browser caching of resources, helping to avoid caching of sensitive data.",
            "X-Frame-Options": "Prevents the website from being embedded in a frame to mitigate Clickjacking attacks.",
            "Referrer-Policy": "Controls the information sent in the Referer header.",
            "Permissions-Policy": "Manages access to browser features.",
            "Expect-CT": "Enforces Certificate Transparency to detect misissued certificates.",
            "Access-Control-Allow-Origin": "Defines permitted origins for CORS requests."
        }

        header_status_table = []
        missing_headers = []
        warnings = []

        with open(log_filename, "a", encoding="utf-8") as log_file:
            log_file.write(f"\nChecking {target}\n")

            for header, description in security_headers.items():
                status = "Found"

                if header not in headers:
                    status = "Missing"
                    missing_headers.append([header, get_header_color(status), description])
                elif header == "Content-Security-Policy":
                    csp = headers["Content-Security-Policy"]
                    issues = []
                    if "unsafe-inline" in csp:
                        issues.append("unsafe-inline")
                    if "unsafe-eval" in csp:
                        issues.append("unsafe-eval")
                    if "data:" in csp:
                        issues.append("data:")

                    if issues:
                        status = f"Found - Multiple Warnings: {'; '.join(issues)}"
                        warnings.append([header, get_header_color(status), description, f"Recommendation: Review CSP for {', '.join(issues)}."])

                elif header == "Strict-Transport-Security":
                    hsts = headers[header]
                    if 'max-age=0' in hsts:
                        status = "Found - Warning"
                        warnings.append([header, get_header_color(status), description, "Recommendation: Ensure a non-zero max-age for stronger security."])
                    if 'includeSubDomains' not in hsts:
                        status = "Found - Warning"
                        warnings.append([header, get_header_color(status), description, "Recommendation: Include 'includeSubDomains' in the HSTS policy."])

                elif header == "X-Content-Type-Options" and headers[header].lower() != "nosniff":
                    status = "Found - Warning"
                    warnings.append([header, get_header_color(status), description, "Recommendation: Set X-Content-Type-Options to 'nosniff' for additional security."])

                elif header == "Referrer-Policy" and headers[header].lower() not in ["strict-origin", "strict-origin-when-cross-origin", "no-referrer"]:
                    status = "Found - Warning"
                    warnings.append([header, get_header_color(status), description, "Recommendation: Use 'strict-origin' or 'no-referrer' for enhanced privacy."])

                elif header == "Permissions-Policy":
                    permissions = headers[header]
                    if "geolocation" not in permissions:
                        warnings.append([header, get_header_color(status), description, "Recommendation: Limit geolocation access in Permissions-Policy."])

                elif header == "Access-Control-Allow-Origin" and headers[header] == "*":
                    status = "Found - Warning"
                    warnings.append([header, get_header_color(status), description, "Recommendation: Avoid wildcard '*' in CORS policy to prevent unauthorized access."])

                if status == "Found":
                    header_status_table.append([header, get_header_color(status), description])

                # Print out each header and its corresponding status
                print(f"{header}: {headers.get(header, 'Header not found')}")
                log_file.write(f"{header}: {status}\n")

        if header_status_table:
            print("\nHeaders Found:")
            print(tabulate(header_status_table, headers=["Header", "Status", "Description"], tablefmt="grid"))

        if missing_headers:
            print("\nMissing Headers:")
            print(tabulate(missing_headers, headers=["Header", "Status", "Description"], tablefmt="grid"))

        if warnings:
            print("\nWarnings Found:")
            print(tabulate(warnings, headers=["Header", "Status", "Description", "Recommendation"], tablefmt="grid"))
        else:
            print("\nNo warnings found.")

    except requests.exceptions.RequestException as e:
        error_message = f"[ERROR] Request failed for {target}: {e}"
        print(error_message)
        with open(log_filename, "a", encoding="utf-8") as log_file:
            log_file.write(error_message + "\n")
    except Exception as e:
        error_message = f"[ERROR] Could not check {target}: {e}"
        print(error_message)
        with open(log_filename, "a", encoding="utf-8") as log_file:
            log_file.write(error_message + "\n")


def main():
    print("""
    ===================================================
                    --checkHEADer--
                    HTTP HEADER CHECKER
                        - by Hasanka Amarasinghe
                        - https://github.com/wrathfuldiety
    ===================================================
    """)

    required_modules = ["requests", "termcolor", "tabulate"]
    install_modules(required_modules)

    print("""
    ===================================================
              Starting the HTTP Header Check
    ===================================================
    """)

    target_url = input("Enter the target URL (e.g., https://www.google.com): ").strip()
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    
    domain_name = sanitize_domain(target_url.split("//")[-1].split("/")[0])
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
    log_filename = f"{domain_name}_header_check_{timestamp}.log"
    
    check_headers(target_url, log_filename)

    print(f"\nHeader check completed. Results are saved in '{log_filename}'.")


if __name__ == "__main__":
    main()

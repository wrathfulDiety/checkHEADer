# checkHEADer
HTTP Header Checker

# HTTP Header Checker

This Python script automates the process of checking important HTTP security headers on a given target URL. It ensures that necessary security headers are present and provides recommendations for any missing or misconfigured headers.

## Features

- **Module Installation**: Automatically installs the required Python modules (`requests`, `termcolor`, `tabulate`) if they are not already installed.
- **Security Header Check**: Checks various HTTP headers like `Content-Security-Policy`, `X-XSS-Protection`, `Strict-Transport-Security`, and others.
- **Logging**: Logs the results of the header check into a timestamped file for review.
- **Recommendations**: Provides actionable security recommendations for headers that are present but misconfigured.
- **Loading Indicator**: Displays a threaded loading animation while modules are being installed.

## Usage

To run the script, execute the following command:

```bash
python header_checker.py

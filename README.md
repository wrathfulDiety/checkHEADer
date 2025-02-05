# checkHEADer
An automation script designed to streamline the process of checking HTTP headers for security issues, reducing manual effort during penetration testing, and saving time for critical findings.


# HTTP Header Checker

This Python script automates the process of checking important HTTP security headers on a given target URL. It ensures that necessary security headers are present and provides recommendations for any missing or misconfigured headers, helping to identify security misconfigurations and improve the security posture of web applications.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [TODO](#todo)
- [License](#license)

---

### Features

- **Automated HTTP Header Checks**: Automatically checks for a range of security headers, including `Content-Security-Policy`, `X-XSS-Protection`, `Strict-Transport-Security`, `Cache-Control`, and more.
- **Header Issue Detection**: Flags missing or misconfigured headers with recommendations to improve security.
- **Detailed Logging**: Logs each header check with status, warnings, and errors.
- **Color-Coded Output**: Makes it easy to identify headers with issues using color-coded feedback.
- **Security Header Checks**: Verifies important HTTP headers to prevent attacks like XSS, clickjacking, and MITM.

---

### Installation

The script automatically installs any missing dependencies. If necessary, it installs the required modules for you.

1. Clone the repository:
    ```bash
    git clone https://github.com/wrathfuldiety/HTTP-Header-Checker.git
    cd HTTP-Header-Checker
    ```

2. Run the script:
    ```bash
    python http_header_checker.py
    ```

This will check for the required dependencies and install them if needed. Ensure you have Python 3+ installed.

---

### Usage

1. **Run the Script**: Run the script using the command:
    ```bash
    python http_header_checker.py
    ```

2. **Enter Target URL**: You will be prompted to enter the target URL, such as `https://example.com`.

3. **View Results**: The script will check the relevant headers and display results directly in the terminal.

4. **Check Logs**: The results will be saved in a log file named after the domain, including detailed status information about each header.

---

## Sample output:

```
Checking headers for https://www.example.com
Content-Security-Policy: Found
Strict-Transport-Security: Found - Warning
X-XSS-Protection: Found Cache-Control: Missing ...

Header check completed. Results are saved in 'example_com_header_check_2025-02-05_12-30-45_123456.log
```

![image](https://github.com/user-attachments/assets/ebbdcd72-2a10-4d68-9601-5e63f1890605)


The log file will include detailed information about the status of each header and any recommendations.

## Recommended Security Headers

The script checks for the following security headers, which are recommended for improving the security of web applications:

- **Content-Security-Policy (CSP)**: Helps mitigate XSS attacks by restricting the sources from which content can be loaded.
- **X-XSS-Protection**: Enables the browser’s XSS filter to block reflected XSS attacks.
- **X-Content-Type-Options**: Prevents browsers from interpreting files as a different MIME type.
- **Strict-Transport-Security (HSTS)**: Forces the use of HTTPS and protects against SSL stripping attacks.
- **Cache-Control**: Prevents the caching of sensitive content.
- **X-Frame-Options**: Protects against clickjacking attacks by preventing the site from being embedded in a frame.
- **Referrer-Policy**: Controls the information sent in the `Referer` header for privacy.
- **Permissions-Policy**: Restricts access to browser features like geolocation and camera.
- **Expect-CT**: Ensures that only valid SSL/TLS certificates are used for the site.
- **Access-Control-Allow-Origin**: Controls the cross-origin resource sharing (CORS) policy for the site.

## Requirements

- Python 3.x
- The script will automatically install the following modules if they are missing:
  - `requests`
  - `termcolor`
  - `tabulate`


### TODO

- [ ] **HTTP Verb Check**: Implement a function to detect unnecessary HTTP methods like `TRACE`, `OPTIONS`, and others, and flag them if they are enabled.
- [ ] **Support for URL List**: Allow the script to accept a list of URLs from a text file (e.g., `urls.txt`), checking all the URLs in the file.
- [ ] **Graceful Error Handling**: Enhance error handling to gracefully skip invalid URLs without crashing the script.
- [ ] **Proxy Support**: Implement an option to route HTTP requests through a proxy server.
- [ ] **Enhanced Logging**: Add more detailed and customizable logging to keep track of each step of the header checking process.
- [ ] **Report Generation**: Generate summary reports of findings in CSV or PDF format for easier sharing with stakeholders.


## Contributions

Contributions are welcome! If you find a bug or would like to improve the project, feel free to fork the repository and submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE), which allows for modification, distribution, and private use. You can find more information in the LICENSE file.

## Author

- **Hasanka Amarasinghe**  
  - [GitHub](https://github.com/wrathfuldiety)
  - [LinkedIn](https://linkedin.com/in/hasanka-amarasinghe)



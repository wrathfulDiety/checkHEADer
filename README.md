# checkHEADer
# HTTP Header Checker

This Python script automates the process of checking important HTTP security headers on a given target URL. It ensures that necessary security headers are present and provides recommendations for any missing or misconfigured headers, helping to identify security misconfigurations and improve the security posture of web applications.

## Features

- **Automatic Module Installation**: The script automatically installs the required Python modules (`requests`, `termcolor`, `tabulate`) if they are not already installed.
- **Security Header Check**: Checks for various important HTTP security headers, including:
  - `Content-Security-Policy`
  - `X-XSS-Protection`
  - `X-Content-Type-Options`
  - `Strict-Transport-Security`
  - `Cache-Control`
  - `X-Frame-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - `Expect-CT`
  - `Access-Control-Allow-Origin`
- **Log Generation**: Outputs the results of the header check into a timestamped log file for easy reference and reporting.
- **Actionable Recommendations**: Provides recommendations for misconfigured or missing headers to enhance security.
- **Loading Indicator**: A threaded loading animation displays while dependencies are being installed.
- **Status Colorization**: The script uses colored output to highlight the status of each header (e.g., green for "Found", red for "Missing", yellow for warnings).

## Installation

This script does not require manual installation of dependencies. It automatically installs the required modules if they are missing.

To run the script, make sure Python is installed on your system. Then, simply clone or download the repository and execute the script.

## Usage

1. Clone or download the repository to your local machine.

2. In your terminal, navigate to the project directory.

3. Run the script using Python:

    ```bash
    python header_checker.py
    ```

4. When prompted, enter the target URL (e.g., `https://www.example.com`).

5. The script will check the headers for the provided target URL and generate a log file with results. You will also see the results printed in the terminal, with color-coded status.

Example output:

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

## License

This project is licensed under the [MIT License](LICENSE), which allows for modification, distribution, and private use. You can find more information in the LICENSE file.

## Author

- **Hasanka Amarasinghe**  
  - [GitHub](https://github.com/wrathfuldiety)
  - [LinkedIn](https://linkedin.com/in/hasanka-amarasinghe)

## Contributions

Contributions are welcome! If you find a bug or would like to improve the project, feel free to fork the repository and submit a pull request.





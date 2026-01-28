# Cloud Foundry Auth Scanner

A security tool to scan Cloud Foundry applications and identify potential unauthorized web interfaces.

## Features

- **Inventory**: Enumerates Orgs, Spaces, and Apps.
- **Static Analysis**: Checks if apps are bound to known Authentication Services (SSO, UAA, LDAP, etc.).
- **Dynamic Analysis**: Probes the app's root URL to check for:
  - Open 200 OK responses (Critical Risk)
  - Redirects to Login (Secure)
  - HTTP 401/403 (Secure)
  - Custom Login Forms (Warning)
- **Reporting**: Colored console output and optional JSON report.

## Installation

1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

**Prerequisites**: You must be logged into Cloud Foundry via the CLI:
```bash
cf login
```

### Modes

1.  **Interactive Mode** (Default):
    Select Orgs and Spaces from a menu.
    ```bash
    ./cf_auth_scanner.py
    ```

2.  **Current Target**:
    Scan only the currently targeted Org/Space (`cf target`).
    ```bash
    ./cf_auth_scanner.py --scope current
    ```

3.  **Config Mode**:
    Scan targets defined in `scan_config.yaml`.
    ```bash
    ./cf_auth_scanner.py --scope config --config scan_config.yaml
    ```

### Output

- **CRITICAL**: App has NO auth services and returns 200 OK on root.
- **HIGH**: App has auth services bound but still returns 200 OK (potential misconfiguration).
- **WARNING**: App returns 200 OK but appears to have a login form (manual verification needed).
- **SECURE**: App returns 401/403 or redirects to a login page.

## Configuration

Edit `scan_config.yaml` to:
- Define specific target Orgs/Spaces.
- Add custom keywords for your organization's Auth Services.
- Adjust timeout and thread settings.

#!/usr/bin/env python3
import sys
import os
import json
import yaml
import requests
import subprocess
import concurrent.futures
import click
import urllib3
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

# --- CONSTANTS ---
AUTH_KEYWORDS_DEFAULT = ["uaa", "sso", "auth", "idp", "oauth", "oidc"]
LOGIN_KEYWORDS = ["login", "auth", "oauth", "sso", "saml", "oidc", "openid", "authorize", "signin", "sign-in"]
LOGIN_PAGE_INDICATORS = [
    '<input type="password"',
    'type="password"',
    "password",
    "sign in",
    "log in", 
    "login",
    "authenticate",
    "oidc",
    "openid",
    "oauth",
    "identity provider",
    "idp",
    "authorization",
]
REDIRECT_CODES = [301, 302, 303, 307, 308]
STATUS_PRIORITY = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "SECURE": 3, "SKIPPED": 4, "UNREACHABLE": 5, "ERROR": 6}


class CFClient:
    """Client for interacting with Cloud Foundry V3 API."""
    
    def __init__(self):
        self.api_endpoint = self._get_api_endpoint()
        self.token = self._get_oauth_token()
        self.headers = {"Authorization": self.token}

    def _get_api_endpoint(self) -> str:
        try:
            output = subprocess.check_output(["cf", "api"], encoding="utf-8")
            for line in output.splitlines():
                if "API endpoint:" in line:
                    return line.split("API endpoint:")[1].strip()
            raise Exception("Could not find API endpoint")
        except subprocess.CalledProcessError:
            console.print("[bold red]Error:[/bold red] 'cf' CLI not found or not logged in.")
            sys.exit(1)

    def _get_oauth_token(self) -> str:
        try:
            return subprocess.check_output(["cf", "oauth-token"], encoding="utf-8").strip()
        except subprocess.CalledProcessError:
            console.print("[bold red]Error:[/bold red] Failed to get OAuth token. Run 'cf login'.")
            sys.exit(1)

    def get(self, path: str, params: Dict = None, fail_on_error: bool = True) -> List[Dict]:
        """GET request with automatic pagination."""
        url = f"{self.api_endpoint}{path}"
        results = []

        while url:
            try:
                response = requests.get(url, headers=self.headers, params=params, verify=False)
                response.raise_for_status()
                data = response.json()

                if "resources" not in data:
                    return data

                results.extend(data["resources"])
                next_page = data.get("pagination", {}).get("next")
                url = next_page["href"] if next_page else None
                params = None

            except requests.exceptions.RequestException as e:
                if fail_on_error:
                    console.print(f"[bold red]API Error:[/bold red] {e}")
                    sys.exit(1)
                if hasattr(e, 'response') and e.response is not None and e.response.status_code == 403:
                    console.print(f"[yellow]Warning: Access denied for {path}. Skipping.[/yellow]")
                else:
                    console.print(f"[yellow]API Warning: {e}[/yellow]")
                return results

        return results

    def get_current_target(self) -> Dict[str, str]:
        try:
            output = subprocess.check_output(["cf", "target"], encoding="utf-8")
            target = {}
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Org:"):
                    target["org"] = line.split("Org:")[1].strip()
                elif line.startswith("Space:"):
                    target["space"] = line.split("Space:")[1].strip()
            return target
        except Exception:
            return {}


class Scanner:
    """Scans CF apps for authentication vulnerabilities."""

    def __init__(self, client: CFClient, config: Dict):
        self.client = client
        self.auth_keywords = config.get("auth_service_keywords", AUTH_KEYWORDS_DEFAULT)
        self.timeout = config.get("settings", {}).get("timeout_seconds", 5)

    def scan_app(self, app: Dict, service_map: Dict[str, Dict]) -> Dict:
        """Analyze a single app for authentication status."""
        app_guid = app["guid"]
        result = {
            "name": app["name"],
            "guid": app_guid,
            "state": app["state"],
            "space_name": "Unknown",
            "org_name": "Unknown",
            "routes": [],
            "bound_services": [],
            "auth_detected": False,
            "status": "UNKNOWN",
            "details": ""
        }

        # Skip stopped apps
        if app["state"] != "STARTED":
            result["status"] = "SKIPPED"
            result["details"] = "App is STOPPED"
            return result

        # Fetch routes
        routes = self._fetch_routes(app_guid)
        if routes is None:
            result["status"] = "ERROR"
            result["details"] = "Failed to fetch routes"
            return result

        result["routes"] = routes
        if not routes:
            result["status"] = "SKIPPED"
            result["details"] = "No public routes"
            return result

        # Check service bindings for auth services
        auth_services = self._check_auth_services(app_guid, service_map)
        result["bound_services"] = auth_services["all"]
        result["auth_detected"] = bool(auth_services["auth"])
        if auth_services["auth"]:
            result["details"] = f"Bound to auth services: {', '.join(auth_services['auth'])}"

        # Probe the endpoint
        self._probe_endpoint(routes[0], result)
        return result

    def _fetch_routes(self, app_guid: str) -> List[str]:
        """Fetch routes for an app. Returns None on error."""
        try:
            routes_data = self.client.get(f"/v3/apps/{app_guid}/routes", fail_on_error=False)
            return [r["url"] for r in routes_data]
        except Exception:
            return None

    def _check_auth_services(self, app_guid: str, service_map: Dict) -> Dict[str, List[str]]:
        """Check if app is bound to auth-related services."""
        result = {"all": [], "auth": []}
        
        try:
            bindings = self.client.get(
                "/v3/service_credential_bindings",
                params={"type": "app", "app_guids": app_guid},
                fail_on_error=False
            )
        except Exception:
            return result

        for binding in bindings:
            svc_guid = (binding.get("relationships", {})
                       .get("service_instance", {})
                       .get("data", {})
                       .get("guid"))
            
            if not svc_guid or svc_guid not in service_map:
                continue

            svc = service_map[svc_guid]
            svc_name = svc["name"]
            result["all"].append(svc_name)

            svc_text = f"{svc_name} {svc.get('offering_name', '')}".lower()
            if any(keyword in svc_text for keyword in self.auth_keywords):
                result["auth"].append(svc_name)

        return result

    def _probe_endpoint(self, route: str, result: Dict) -> None:
        """Probe the endpoint and update result with security status."""
        url = route if route.startswith("http") else f"https://{route}"

        try:
            resp = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
        except requests.RequestException as e:
            result["status"] = "UNREACHABLE"
            self._append_detail(result, f"Connection error: {e}")
            return

        status_code = resp.status_code

        if status_code in REDIRECT_CODES:
            location = resp.headers.get("Location", "").lower()
            if any(kw in location for kw in LOGIN_KEYWORDS):
                result["status"] = "SECURE"
                self._append_detail(result, "Redirects to login")
            else:
                result["status"] = "WARNING"
                self._append_detail(result, f"Redirects to {location}")

        elif status_code in [401, 403]:
            result["status"] = "SECURE"
            self._append_detail(result, "Returns 401/403")

        elif status_code == 200:
            self._classify_200_response(resp.text, result)

        else:
            result["status"] = "WARNING"
            self._append_detail(result, f"Returns HTTP {status_code}")

    def _classify_200_response(self, content: str, result: Dict) -> None:
        """Classify a 200 OK response."""
        content_lower = content.lower()
        
        # Check for login/auth page indicators
        login_indicators_found = [ind for ind in LOGIN_PAGE_INDICATORS if ind in content_lower]
        has_login_page = bool(login_indicators_found)

        if has_login_page:
            result["status"] = "SECURE"
            self._append_detail(result, f"Login page detected ({login_indicators_found[0]})")
        elif result["auth_detected"]:
            result["status"] = "HIGH"
            self._append_detail(result, "Auth service bound but root returns 200 OK")
        else:
            result["status"] = "CRITICAL"
            result["details"] = "OPEN WEB INTERFACE (No Auth Service + 200 OK)"

    def _append_detail(self, result: Dict, detail: str) -> None:
        """Append detail to result, handling separator."""
        if result["details"]:
            result["details"] += f" | {detail}"
        else:
            result["details"] = detail


def parse_selection(selection: str, items: List[Dict], key: str = "name") -> List[Dict]:
    """Parse user selection (numbers or names) into list of items."""
    if selection.lower() == "all":
        return items

    selected = []
    for inp in [x.strip() for x in selection.split(",")]:
        if inp.isdigit():
            idx = int(inp) - 1
            if 0 <= idx < len(items):
                selected.append(items[idx])
        else:
            match = next((item for item in items if item[key].lower() == inp.lower()), None)
            if match:
                selected.append(match)
            else:
                console.print(f"[yellow]Warning: '{inp}' not found.[/yellow]")
    return selected


def get_org_name(space: Dict, orgs: List[Dict]) -> str:
    """Get org name for a space."""
    org_guid = space.get("relationships", {}).get("organization", {}).get("data", {}).get("guid")
    for org in orgs:
        if org["guid"] == org_guid:
            return org["name"]
    return "Unknown"


def load_config(path: str) -> Dict:
    """Load configuration from YAML file."""
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                return yaml.safe_load(f) or {}
    except Exception as e:
        console.print(f"[bold red]Error loading config:[/bold red] {e}")
    return {}


def select_scope_current(client: CFClient) -> tuple:
    """Select scope from current cf target."""
    current = client.get_current_target()
    if not current.get("org") or not current.get("space"):
        console.print("[red]No org/space currently targeted.[/red]")
        sys.exit(1)

    orgs = client.get("/v3/organizations", params={"names": current["org"]})
    if not orgs:
        console.print(f"[red]Org {current['org']} not found.[/red]")
        sys.exit(1)

    spaces = client.get("/v3/spaces", params={
        "names": current["space"],
        "organization_guids": orgs[0]["guid"]
    })
    return orgs, spaces


def select_scope_config(client: CFClient, app_config: Dict) -> tuple:
    """Select scope from config file."""
    if "targets" not in app_config:
        console.print("[red]No 'targets' defined in config file.[/red]")
        sys.exit(1)

    target_orgs = []
    target_spaces = []

    for target in app_config["targets"]:
        org_name = target["org"]
        space_names = target["spaces"]

        orgs = client.get("/v3/organizations", params={"names": org_name})
        if not orgs:
            console.print(f"[yellow]Org {org_name} not found, skipping.[/yellow]")
            continue

        org = orgs[0]
        target_orgs.append(org)

        if "*" in space_names:
            spaces = client.get("/v3/spaces", params={"organization_guids": org["guid"]})
        else:
            spaces = client.get("/v3/spaces", params={
                "organization_guids": org["guid"],
                "names": ",".join(space_names)
            })
        target_spaces.extend(spaces)

    return target_orgs, target_spaces


def select_scope_interactive(client: CFClient) -> tuple:
    """Select scope interactively."""
    with console.status("Fetching organizations..."):
        all_orgs = client.get("/v3/organizations")

    console.print("\n[bold]Available Organizations:[/bold]")
    for i, org in enumerate(all_orgs):
        console.print(f" {i+1}. {org['name']}")

    selection = click.prompt("Select Orgs (comma separated numbers or names, or 'all')", default="all")
    selected_orgs = parse_selection(selection, all_orgs)

    if not selected_orgs:
        console.print("[red]No valid organizations selected. Exiting.[/red]")
        sys.exit(0)

    org_guids = ",".join(o["guid"] for o in selected_orgs)
    with console.status("Fetching spaces..."):
        all_spaces = client.get(f"/v3/spaces?organization_guids={org_guids}")

    console.print("\n[bold]Available Spaces:[/bold]")
    for i, space in enumerate(all_spaces):
        org_name = get_org_name(space, selected_orgs)
        console.print(f" {i+1}. {org_name} / {space['name']}")

    selection = click.prompt("Select Spaces (comma separated numbers or names, or 'all')", default="all")
    selected_spaces = parse_selection(selection, all_spaces)

    return selected_orgs, selected_spaces


def fetch_space_resources(client: CFClient, space: Dict) -> tuple:
    """Fetch apps and service instances for a single space. Returns (apps, services)."""
    space_guid = space["guid"]
    apps = []
    services = []

    try:
        services = client.get("/v3/service_instances", params={"space_guids": space_guid}, fail_on_error=False)
    except Exception:
        pass

    try:
        apps = client.get("/v3/apps", params={"space_guids": space_guid, "per_page": 50}, fail_on_error=False)
    except Exception:
        pass

    return apps, services


def fetch_resources(client: CFClient, target_spaces: List[Dict], max_threads: int, progress) -> tuple:
    """Fetch apps and service instances for all target spaces in parallel."""
    all_apps = []
    service_map = {}

    task = progress.add_task("Fetching resources...", total=len(target_spaces))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(fetch_space_resources, client, space): space for space in target_spaces}

        for future in concurrent.futures.as_completed(futures):
            space = futures[future]
            progress.update(task, description=f"Fetched: {space['name']}")
            
            try:
                apps, services = future.result()
                all_apps.extend(apps)
                for svc in services:
                    service_map[svc["guid"]] = {"name": svc["name"], "type": svc["type"], "offering_name": ""}
            except Exception:
                pass

            progress.update(task, advance=1)

    return all_apps, service_map


def scan_apps(scanner: Scanner, apps: List[Dict], service_map: Dict, max_threads: int, progress) -> List[Dict]:
    """Scan all apps in parallel."""
    results = []
    task = progress.add_task("Scanning apps...", total=len(apps))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scanner.scan_app, app, service_map): app for app in apps}

        for future in concurrent.futures.as_completed(futures):
            app = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                console.print(f"[red]Exception scanning {app['name']}: {exc}[/red]")
            progress.update(task, advance=1)

    return results


def enrich_results(results: List[Dict], space_map: Dict, target_orgs: List[Dict]) -> None:
    """Add org/space names to results."""
    for result in results:
        space_guid = result.get("guid")
        # Find app's space from the original app data - need to look up differently
        # Actually results don't have the space relationship, need to fix this
        pass


def print_results(results: List[Dict]) -> None:
    """Print results table with clickable app names."""
    results.sort(key=lambda x: STATUS_PRIORITY.get(x["status"], 99))

    table = Table(title="Scan Results", box=box.ROUNDED)
    table.add_column("Org", style="cyan")
    table.add_column("Space", style="cyan")
    table.add_column("App", style="white")
    table.add_column("Status", style="bold")
    table.add_column("Details", style="dim")

    status_styles = {
        "CRITICAL": "bold red reverse",
        "HIGH": "bold red",
        "WARNING": "yellow",
        "UNREACHABLE": "magenta"
    }

    for r in results:
        style = status_styles.get(r["status"], "green")
        
        # Make app name a clickable link if it has routes
        routes = r.get("routes", [])
        if routes:
            url = routes[0] if routes[0].startswith("http") else f"https://{routes[0]}"
            app_display = f"[link={url}]{r['name']}[/link]"
        else:
            app_display = r["name"]
        
        table.add_row(
            r["org_name"],
            r["space_name"],
            app_display,
            f"[{style}]{r['status']}[/{style}]",
            r["details"]
        )

    console.print(table)


@click.command()
@click.option("--scope", type=click.Choice(["interactive", "config", "current"]), default="interactive", help="Scope selection mode")
@click.option("--config", "config_path", default="scan_config.yaml", help="Path to configuration file")
@click.option("--output", help="Output file for JSON report")
def main(scope, config_path, output):
    """Cloud Foundry Auth Scanner - Find apps with no authentication."""
    app_config = load_config(config_path)
    client = CFClient()
    scanner = Scanner(client, app_config)

    console.print(f"[bold blue]CF Auth Scanner[/bold blue] | Endpoint: {client.api_endpoint}")

    # Select scope
    if scope == "current":
        target_orgs, target_spaces = select_scope_current(client)
    elif scope == "config":
        target_orgs, target_spaces = select_scope_config(client, app_config)
    else:
        target_orgs, target_spaces = select_scope_interactive(client)

    if not target_spaces:
        console.print("[red]No spaces selected. Exiting.[/red]")
        sys.exit(0)

    space_map = {s["guid"]: s for s in target_spaces}
    max_threads = app_config.get("settings", {}).get("max_threads", 10)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        all_apps, service_map = fetch_resources(client, target_spaces, max_threads, progress)

        if not all_apps:
            console.print("[yellow]No apps found in selected spaces.[/yellow]")
            results = []
        else:
            results = scan_apps(scanner, all_apps, service_map, max_threads, progress)

            # Enrich with org/space names
            for app, result in zip(all_apps, results):
                space_guid = app["relationships"]["space"]["data"]["guid"]
                if space_guid in space_map:
                    result["space_name"] = space_map[space_guid]["name"]
                    result["org_name"] = get_org_name(space_map[space_guid], target_orgs)

    print_results(results)

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"Report saved to {output}")


if __name__ == "__main__":
    main()

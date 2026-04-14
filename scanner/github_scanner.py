import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

from .dep_registry import check_package


@dataclass
class DependencyFinding:
    package_name:    str
    version:         Optional[str]
    dep_file:        str
    ecosystem:       str
    risk:            str
    reason:          str
    fix:             str
    is_pqc_positive: bool = False

    def to_dict(self) -> dict:
        return {
            "package":    self.package_name,
            "version":    self.version,
            "file":       self.dep_file,
            "ecosystem":  self.ecosystem,
            "risk":       self.risk,
            "reason":     self.reason,
            "fix":        self.fix,
            "is_pqc":     self.is_pqc_positive,
        }


@dataclass
class GithubScanResult:
    repo:                str
    dependency_findings: List[DependencyFinding] = field(default_factory=list)
    pqc_signals:         List[str] = field(default_factory=list)
    errors:              List[str] = field(default_factory=list)

    @property
    def critical_count(self):
        return sum(1 for d in self.dependency_findings if d.risk == "CRITICAL")

    @property
    def high_count(self):
        return sum(1 for d in self.dependency_findings if d.risk == "HIGH")

    def to_dict(self) -> dict:
        return {
            "repo":          self.repo,
            "critical_deps": self.critical_count,
            "high_deps":     self.high_count,
            "findings":      [d.to_dict() for d in self.dependency_findings],
            "pqc_signals":   self.pqc_signals,
            "errors":        self.errors,
        }


class GitHubScanner:

    API = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        # Read from env var automatically — no token needed in code
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self._headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            self._headers["Authorization"] = f"Bearer {self.token}"
        else:
            print("Warning: no GITHUB_TOKEN set — rate limited to 60 requests/hour")

    def scan_repo(self, repo_url: str) -> GithubScanResult:
        owner, repo = self._parse_url(repo_url)
        result = GithubScanResult(repo=f"{owner}/{repo}")

        if not owner:
            result.errors.append(f"Cannot parse GitHub URL: {repo_url}")
            return result

        # Get the full file tree from GitHub API
        tree = self._get(f"/repos/{owner}/{repo}/git/trees/HEAD?recursive=1")
        if not tree:
            result.errors.append(
                "Could not fetch repo tree — check GITHUB_TOKEN and repo URL"
            )
            return result

        # Every supported dependency file and its parser
        dep_files = {
            "requirements.txt":      self._parse_requirements,
            "requirements-dev.txt":  self._parse_requirements,
            "requirements-prod.txt": self._parse_requirements,
            "Pipfile":               self._parse_pipfile,
            "pyproject.toml":        self._parse_pyproject,
            "package.json":          self._parse_package_json,
            "go.mod":                self._parse_go_mod,
            "Cargo.toml":            self._parse_cargo,
            "pom.xml":               self._parse_pom,
            "build.gradle":          self._parse_gradle,
            "build.gradle.kts":      self._parse_gradle,
            "Gemfile":               self._parse_gemfile,
            "composer.json":         self._parse_composer,
            "*.csproj":              self._parse_csproj,
            "packages.config":       self._parse_packages_config,
        }

        # Walk the repo tree and parse any dep files found
        for item in tree.get("tree", []):
            path     = item.get("path", "")
            filename = path.split("/")[-1]

            if item.get("type") != "blob":
                continue

            # Check exact filename match
            if filename in dep_files:
                content = self._fetch_raw(owner, repo, path)
                if content:
                    findings = dep_files[filename](content, path)
                    result.dependency_findings.extend(findings)
        # Deduplicate — same package in multiple dep files counts once
        seen = set()
        unique = []
        for d in result.dependency_findings:
            key = (d.package_name.lower(), d.risk)
            if key not in seen:
                seen.add(key)
                unique.append(d)
            result.dependency_findings = unique    
        
        # Collect PQC positive signals
        for d in result.dependency_findings:
            if d.is_pqc_positive:
                result.pqc_signals.append(
                    f"PQC library detected: {d.package_name} ({d.ecosystem})"
                )

        return result

    # ── GitHub API helpers ────────────────────────────────────────────────────

    def _parse_url(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        m = re.search(r'github\.com[/:]([^/]+)/([^/.\s]+?)(?:\.git)?$', url)
        if m:
            return m.group(1), m.group(2)
        m = re.match(r'^([^/]+)/([^/]+)$', url)
        if m:
            return m.group(1), m.group(2)
        return None, None

    def _get(self, endpoint: str) -> Optional[dict]:
        req = Request(f"{self.API}{endpoint}", headers=self._headers)
        try:
            with urlopen(req, timeout=15) as r:
                return json.loads(r.read().decode())
        except HTTPError as e:
            if e.code == 403:
                print("GitHub rate limit hit — set GITHUB_TOKEN env var")
            elif e.code == 404:
                print(f"Repo not found: {endpoint}")
            return None
        except URLError as e:
            print(f"Network error: {e}")
            return None

    def _fetch_raw(self, owner: str, repo: str, path: str) -> Optional[str]:
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}"
        try:
            with urlopen(Request(url), timeout=10) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception:
            return None

    def _make_finding(self, result: Optional[dict]) -> Optional[DependencyFinding]:
        if not result:
            return None
        return DependencyFinding(
            package_name    = result["package"],
            version         = result["version"],
            dep_file        = result["file"],
            ecosystem       = result["ecosystem"],
            risk            = result["risk"],
            reason          = result["reason"],
            fix             = result["fix"],
            is_pqc_positive = result["is_pqc"],
        )

    # ── Dependency file parsers ───────────────────────────────────────────────

    def _parse_requirements(self, content: str, filepath: str) -> List[DependencyFinding]:
        findings = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*([><=!~].*)?$', line)
            if m:
                f = self._make_finding(
                    check_package(m.group(1), m.group(2), filepath)
                )
                if f:
                    findings.append(f)
        return findings

    def _parse_pipfile(self, content: str, filepath: str) -> List[DependencyFinding]:
        findings = []
        for line in content.splitlines():
            m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=', line)
            if m:
                f = self._make_finding(
                    check_package(m.group(1), None, filepath)
                )
                if f:
                    findings.append(f)
        return findings

    def _parse_pyproject(self, content: str, filepath: str) -> List[DependencyFinding]:
        findings = []
        for m in re.finditer(r'"([A-Za-z0-9_\-\.]+)\s*([><=!~][^"]*)"', content):
            f = self._make_finding(
                check_package(m.group(1), m.group(2), filepath)
            )
            if f:
                findings.append(f)
        return findings

    def _parse_package_json(self, content: str, filepath: str) -> List[DependencyFinding]:
        findings = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return findings
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for pkg, ver in data.get(section, {}).items():
                f = self._make_finding(
                    check_package(pkg, str(ver), filepath)
                )
                if f:
                    findings.append(f)
        return findings

    def _parse_go_mod(self, content: str, filepath: str) -> List[DependencyFinding]:
        findings = []
        for line in content.splitlines():
            m = re.match(r'^\s+([^\s]+)\s+v([^\s]+)', line)
            if m:
                # Use full module path for Go
                f = self._make_finding(
                    check_package(m.group(1), m.group(2), filepath)
                )
                if f:
                    findings.append(f)
        return findings

    def _parse_cargo(self, content: str, filepath: str) -> List[DependencyFinding]:
        findings = []
        for line in content.splitlines():
            m = re.match(r'^([a-z0-9_\-]+)\s*=', line)
            if m:
                f = self._make_finding(
                    check_package(m.group(1), None, filepath)
                )
                if f:
                    findings.append(f)
        return findings

    def _parse_pom(self, content: str, filepath: str) -> List[DependencyFinding]:
        findings = []
        for m in re.finditer(r'<artifactId>([^<]+)</artifactId>', content):
            f = self._make_finding(
                check_package(m.group(1), None, filepath)
            )
            if f:
                findings.append(f)
        return findings

    def _parse_gradle(self, content: str, filepath: str) -> List[DependencyFinding]:
        findings = []
        for m in re.finditer(
            r'["\']([^"\']+):([^"\']+):([^"\']+)["\']', content
        ):
            f = self._make_finding(
                check_package(m.group(2), m.group(3), filepath)
            )
            if f:
                findings.append(f)
        return findings

    def _parse_gemfile(self, content: str, filepath: str) -> List[DependencyFinding]:
        findings = []
        for line in content.splitlines():
            m = re.match(r"^\s*gem\s+['\"]([^'\"]+)['\"]", line)
            if m:
                f = self._make_finding(
                    check_package(m.group(1), None, filepath)
                )
                if f:
                    findings.append(f)
        return findings

    def _parse_composer(self, content: str, filepath: str) -> List[DependencyFinding]:
        findings = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return findings
        for section in ("require", "require-dev"):
            for pkg, ver in data.get(section, {}).items():
                f = self._make_finding(
                    check_package(pkg, str(ver), filepath)
                )
                if f:
                    findings.append(f)
        return findings

    def _parse_csproj(self, content: str, filepath: str) -> List[DependencyFinding]:
        findings = []
        for m in re.finditer(
            r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"',
            content
        ):
            f = self._make_finding(
                check_package(m.group(1), m.group(2), filepath)
            )
            if f:
                findings.append(f)
        return findings

    def _parse_packages_config(self, content: str, filepath: str) -> List[DependencyFinding]:
        findings = []
        for m in re.finditer(
            r'<package\s+id="([^"]+)"\s+version="([^"]+)"',
            content
        ):
            f = self._make_finding(
                check_package(m.group(1), m.group(2), filepath)
            )
            if f:
                findings.append(f)
        return findings
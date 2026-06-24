import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List

from .code_scanner import ScanResult, CodeScanner
from .github_scanner import GithubScanResult, GitHubScanner

@dataclass
class PostureReport:
    target:          str
    scanned_at:      str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    code_scan:       Optional[ScanResult]       = None
    github_scan:     Optional[GithubScanResult] = None
    overall_score:   float = 0.0
    overall_grade:   str   = "F"
    summary:         str   = ""
    recommendations: List[str] = field(default_factory=list)

    def compute(self):
        """Combine both scans into one overall score and grade."""
        scores = []

        if self.code_scan and self.code_scan.posture_score is not None:
            scores.append(self.code_scan.posture_score)

        if self.github_scan:
            # Convert dep findings into a score
            dep_penalty = (
                self.github_scan.critical_count * 20 +
                self.github_scan.high_count     * 10
            )
            dep_score = max(0.0, 100.0 - dep_penalty)

            # Bonus for positive PQC signals — max 10 points
            bonus = min(len(self.github_scan.pqc_signals) * 5, 10)
            dep_score = min(dep_score + bonus, 100.0)
            scores.append(dep_score)

        if scores:
            self.overall_score = round(sum(scores) / len(scores), 1)
        else:
            self.overall_score = 0.0

        # Assign grade
        if self.overall_score >= 90:   self.overall_grade = "A"
        elif self.overall_score >= 75: self.overall_grade = "B"
        elif self.overall_score >= 55: self.overall_grade = "C"
        elif self.overall_score >= 35: self.overall_grade = "D"
        else:                          self.overall_grade = "F"

        self._build_summary()
        self._build_recommendations()

    def _build_summary(self):
        lines = [f"PQC Posture Report — {self.target}"]
        lines.append(
            f"Overall Score: {self.overall_score}/100 (Grade: {self.overall_grade})"
        )

        if self.code_scan:
            lines.append(
                f"Code Scan: {self.code_scan.files_scanned} files, "
                f"{len(self.code_scan.findings)} findings "
                f"({self.code_scan.critical_count} CRITICAL, "
                f"{self.code_scan.high_count} HIGH)."
            )
            hndl = [
                f for f in self.code_scan.findings
                if f.pattern.harvest_now_risk
            ]
            if hndl:
                lines.append(
                    f"WARNING: {len(hndl)} finding(s) carry Harvest Now "
                    f"Decrypt Later risk. Encrypted data sent today could "
                    f"be decrypted by a future quantum computer."
                )

        if self.github_scan:
            lines.append(
                f"Dependency Scan: "
                f"{len(self.github_scan.dependency_findings)} "
                f"vulnerable libraries found."
            )
            if self.github_scan.pqc_signals:
                lines.append(
                    f"Positive: {len(self.github_scan.pqc_signals)} "
                    f"PQC library/libraries already in use."
                )

        self.summary = " ".join(lines)

    def _build_recommendations(self):
        recs = []

        # From code findings — most severe first
        if self.code_scan:
            seen_algos = set()
            sorted_findings = sorted(
                self.code_scan.findings,
                key=lambda f: f.pattern.risk.value
            )
            for f in sorted_findings:
                algo = f.pattern.algorithm
                if algo not in seen_algos:
                    seen_algos.add(algo)
                    recs.append(
                        f"[{f.pattern.risk.value}] Replace {algo} with "
                        f"{f.pattern.nist_replacement} — "
                        f"first seen at {f.file_path}:{f.line_number}. "
                        f"Regulated by: {f.pattern.regulations}. "
                        f"Disallowed after: {f.pattern.disallowed_after}."
                    )

        # From dependency findings
        if self.github_scan:
            for d in self.github_scan.dependency_findings:
                if not d.is_pqc_positive:
                    recs.append(
                        f"[{d.risk}] Remove or replace '{d.package_name}' "
                        f"({d.ecosystem}): {d.reason}. "
                        f"Recommended fix: {d.fix}."
                    )

        self.recommendations = recs[:15]  # top 15

    def to_dict(self) -> dict:
        return {
            "pqc_posture_report": {
                "target":          self.target,
                "scanned_at":      self.scanned_at,
                "overall_score":   self.overall_score,
                "overall_grade":   self.overall_grade,
                "summary":         self.summary,
                "recommendations": self.recommendations,
                "code_scan":       self.code_scan.to_dict()
                                   if self.code_scan else None,
                "github_scan":     self.github_scan.to_dict()
                                   if self.github_scan else None,
            }
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_markdown(self) -> str:
        lines = [
            "# PQC Posture Report",
            f"**Target:** {self.target}",
            f"**Scanned:** {self.scanned_at}",
            f"**Score:** {self.overall_score}/100 — Grade **{self.overall_grade}**",
            "",
            "---",
            "",
            "## Summary",
            "",
            self.summary,
            "",
            "---",
            "",
            "## Top Recommendations",
            "",
        ]

        for i, rec in enumerate(self.recommendations, 1):
            lines.append(f"{i}. {rec}")

        if self.code_scan and self.code_scan.findings:
            lines += [
                "",
                "---",
                "",
                "## Code Findings",
                "",
                "| Risk | Algorithm | File | Line | Deadline |",
                "|------|-----------|------|------|----------|",
            ]
            for f in self.code_scan.findings:
                lines.append(
                    f"| {f.pattern.risk.value} "
                    f"| {f.pattern.algorithm} "
                    f"| {f.file_path} "
                    f"| {f.line_number} "
                    f"| {f.pattern.disallowed_after} |"
                )

        if self.github_scan and self.github_scan.dependency_findings:
            lines += [
                "",
                "---",
                "",
                "## Dependency Findings",
                "",
                "| Risk | Package | Ecosystem | Fix |",
                "|------|---------|-----------|-----|",
            ]
            for d in self.github_scan.dependency_findings:
                lines.append(
                    f"| {d.risk} "
                    f"| {d.package_name} "
                    f"| {d.ecosystem} "
                    f"| {d.fix} |"
                )

        lines += [
            "",
            "---",
            "",
            "## NIST PQC Standards",
            "",
            "| Standard | Algorithm | Use Case |",
            "|----------|-----------|----------|",
            "| FIPS 203 | ML-KEM (CRYSTALS-Kyber) | Key Exchange |",
            "| FIPS 204 | ML-DSA (CRYSTALS-Dilithium) | Digital Signatures |",
            "| FIPS 205 | SLH-DSA (SPHINCS+) | Hash-based Signatures |",
        ]

        return "\n".join(lines)
    
class PostureScanner:
    """
    Runs both scanners and returns a unified PostureReport.
    This is the main entry point for the API.
    """

    def __init__(self, github_token: str = None):
        self.github_token = github_token

    def scan_github_repo(self, repo_url: str) -> PostureReport:
        """Full scan — GitHub deps + local code scan via clone."""
        import tempfile, shutil, subprocess
        from pathlib import Path

        report = PostureReport(target=repo_url)

        # 1. GitHub dependency scan — fast, no clone needed
        print(f"Scanning dependencies: {repo_url}")
        gh = GitHubScanner(token=self.github_token)
        report.github_scan = gh.scan_repo(repo_url)

        # 2. Clone and code scan
        tmpdir = tempfile.mkdtemp(prefix="pqc_")
        try:
            print(f"Cloning repo...")
            result = subprocess.run(
                ["git", "clone", "--depth=1", repo_url, tmpdir],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                print(f"Scanning code...")
                scanner = CodeScanner()
                report.code_scan = scanner.scan_directory(tmpdir)
                report.code_scan.target = repo_url
            else:
                print(f"Clone failed: {result.stderr.strip()}")

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        report.compute()
        return report

    def scan_local(
        self,
        path: str,
        repo_url: str = None
    ) -> PostureReport:
        """Scan a local directory, optionally also run GitHub dep scan."""
        report = PostureReport(target=path)

        print(f"Scanning code: {path}")
        scanner = CodeScanner()
        report.code_scan = scanner.scan_directory(path)

        if repo_url:
            print(f"Scanning dependencies: {repo_url}")
            gh = GitHubScanner(token=self.github_token)
            report.github_scan = gh.scan_repo(repo_url)
            report.target = repo_url

        report.compute()
        return report
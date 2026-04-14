import re
import os
import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from .patterns import CryptoPattern, RiskLevel, ALL_PATTERNS


# ── Constants ─────────────────────────────────────────────────────────────────

SCANNABLE_EXTENSIONS = {
    # Python
    ".py", ".pyx",
    # JavaScript / TypeScript
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    # Java / JVM
    ".java", ".kt", ".kts", ".groovy", ".scala",
    # Go
    ".go",
    # Rust
    ".rs",
    # C / C++
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
    # .NET
    ".cs", ".vb",
    # Ruby
    ".rb",
    # PHP
    ".php",
    # Swift / Objective-C
    ".swift", ".m",
    # Shell
    ".sh", ".bash", ".zsh",
    # Config / Infrastructure
    ".yaml", ".yml",
    ".json",
    ".toml",
    ".tf", ".tfvars",
    ".hcl",
    ".env",
    ".properties",
    ".xml",
    ".gradle",
    # Other languages
    ".dart",
    ".ex", ".exs",
    ".lua",
    ".r",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__",
    "venv", ".venv", "dist", "build",
}

SKIP_FILE_PATTERNS = [
    "patterns.py",
    "test_*.py",
    "*_test.py",
    "*_mock.py",
    "mock_*.py",
    "fake_*.py",
    "stub_*.py",
    "*_stub.py",
    "conftest.py",
]

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


# ── Finding ───────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    file_path:    str
    line_number:  int
    line_content: str
    pattern:      CryptoPattern
    matched_text: str

    def to_dict(self) -> dict:
        return {
            "file":             self.file_path,
            "line":             self.line_number,
            "matched_text":     self.matched_text,
            "line_content":     self.line_content.strip(),
            "algorithm":        self.pattern.algorithm,
            "risk":             self.pattern.risk.value,
            "description":      self.pattern.description,
            "recommendation":   self.pattern.recommendation,
            "nist_replacement": self.pattern.nist_replacement,
            "harvest_now_risk": self.pattern.harvest_now_risk,
        }


# ── ScanResult ────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    target:        str
    findings:      List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors:        List[str] = field(default_factory=list)
    posture_score: Optional[float] = None
    posture_grade: Optional[str]  = None

    @property
    def critical_count(self):
        return sum(1 for f in self.findings if f.pattern.risk == RiskLevel.CRITICAL)

    @property
    def high_count(self):
        return sum(1 for f in self.findings if f.pattern.risk == RiskLevel.HIGH)

    def compute_posture_score(self):
        penalty = (self.critical_count * 20) + (self.high_count * 10)
        score = max(0.0, 100.0 - penalty)
        self.posture_score = round(score, 1)

        if score >= 90:   self.posture_grade = "A"
        elif score >= 75: self.posture_grade = "B"
        elif score >= 55: self.posture_grade = "C"
        elif score >= 35: self.posture_grade = "D"
        else:             self.posture_grade = "F"

    def to_dict(self) -> dict:
        return {
            "target":         self.target,
            "files_scanned":  self.files_scanned,
            "total_findings": len(self.findings),
            "critical":       self.critical_count,
            "high":           self.high_count,
            "posture_score":  self.posture_score,
            "posture_grade":  self.posture_grade,
            "findings":       [f.to_dict() for f in self.findings],
        }


# ── CodeScanner ───────────────────────────────────────────────────────────────

class CodeScanner:

    def __init__(
        self,
        patterns: List[CryptoPattern] = None,
        extra_skip_patterns: List[str] = None,
    ):
        self.patterns = patterns or ALL_PATTERNS
        self.skip_file_patterns = SKIP_FILE_PATTERNS.copy()
        if extra_skip_patterns:
            self.skip_file_patterns.extend(extra_skip_patterns)

        # Compile all regex patterns once at startup — faster than per-file
        self._compiled = []
        for p in self.patterns:
            try:
                compiled = re.compile(p.pattern, re.IGNORECASE)
                self._compiled.append((compiled, p))
            except re.error as e:
                print(f"Warning: bad pattern '{p.name}': {e}")

    def scan_directory(self, directory: str) -> ScanResult:
        root = Path(directory).resolve()
        result = ScanResult(target=str(root))

        for path in self._walk(root):
            findings, error = self._scan_file(path, root)
            if error:
                result.errors.append(error)
                result.files_skipped += 1
            else:
                result.findings.extend(findings)
                result.files_scanned += 1

        result.compute_posture_score()
        return result

    def _walk(self, root: Path):
        for dirpath, dirnames, filenames in os.walk(root):
            # Skip unwanted directories
            dirnames[:] = [
                d for d in dirnames
                if d not in SKIP_DIRS and not d.startswith(".")
            ]
            for filename in filenames:
                # Skip test, mock, fixture files
                if any(fnmatch.fnmatch(filename, p) for p in self.skip_file_patterns):
                    continue
                filepath = Path(dirpath) / filename
                if filepath.suffix.lower() in SCANNABLE_EXTENSIONS:
                    yield filepath

    def _scan_file(
        self, path: Path, base: Path
    ) -> Tuple[List[Finding], Optional[str]]:

        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                return [], f"Skipped (too large): {path}"

            content  = path.read_text(encoding="utf-8", errors="replace")
            lines    = content.splitlines()
            rel_path = str(path.relative_to(base))
            findings = []
            seen     = set()

            for compiled_re, pattern in self._compiled:
                for match in compiled_re.finditer(content):
                    line_no   = content[: match.start()].count("\n") + 1
                    dedup_key = (pattern.name, line_no)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    line_content = lines[line_no - 1] if line_no <= len(lines) else ""

                    # Skip comment lines
                    stripped = line_content.strip()
                    if stripped.startswith(("#", "//", "*", "<!--")):
                        continue

                    findings.append(Finding(
                        file_path    = rel_path,
                        line_number  = line_no,
                        line_content = line_content,
                        pattern      = pattern,
                        matched_text = match.group(0),
                    ))

            return findings, None

        except Exception as e:
            return [], f"Error scanning {path}: {e}"
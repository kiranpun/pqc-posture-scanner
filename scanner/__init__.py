def __init__(
    self,
    patterns: List[CryptoPattern] = None,
    extra_skip_patterns: List[str] = None,
):
    self.patterns = patterns or ALL_PATTERNS
    self.skip_file_patterns = SKIP_FILE_PATTERNS.copy()
    if extra_skip_patterns:
        self.skip_file_patterns.extend(extra_skip_patterns)

    # Compile all regex patterns once at startup
    self._compiled = []
    for p in self.patterns:
        try:
            compiled = re.compile(p.pattern, re.IGNORECASE)
            self._compiled.append((compiled, p))
        except re.error as e:
            print(f"Warning: bad pattern '{p.name}': {e}")
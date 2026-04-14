from scanner.github_scanner import GitHubScanner

scanner = GitHubScanner()

# Test against multiple public repos
repos = [
    "https://github.com/DarshanC27/quantum_ready_scanner",
    "https://github.com/paramiko/paramiko",      # Python SSH library
    "https://github.com/jpadilla/pyjwt",         # PyJWT
]

for repo_url in repos:
    print(f"\n{'='*50}")
    result = scanner.scan_repo(repo_url)
    print(f"Repo          : {result.repo}")
    print(f"Critical deps : {result.critical_count}")
    print(f"High deps     : {result.high_count}")
    print(f"Total findings: {len(result.dependency_findings)}")

    for d in result.dependency_findings:
        print(f"\n  [{d.risk}] {d.package_name} ({d.ecosystem})")
        print(f"  Reason : {d.reason}")
        print(f"  Fix    : {d.fix}")

    if result.errors:
        for e in result.errors:
            print(f"  Error: {e}")
from scanner.posture_report import PostureScanner

scanner = PostureScanner()

# Full scan — code + dependencies together
report = scanner.scan_github_repo(
    "https://github.com/DarshanC27/quantum_ready_scanner"
)

# Print the markdown report
print(report.to_markdown())

# Also save as JSON
with open("report.json", "w") as f:
    f.write(report.to_json())

print("\nJSON report saved to report.json")
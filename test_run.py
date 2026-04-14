from scanner.code_scanner import CodeScanner

result = CodeScanner().scan_directory('.')

print(f"Files scanned : {result.files_scanned}")
print(f"Findings      : {len(result.findings)}")
print(f"Score         : {result.posture_score} ({result.posture_grade})")
print()

if result.findings:
    print("--- Findings ---")
    for f in result.findings:
        print(f"[{f.pattern.risk.value}] {f.pattern.algorithm}")
        print(f"  File : {f.file_path}:{f.line_number}")
        print(f"  Line : {f.line_content.strip()}")
        print(f"  Fix  : {f.pattern.recommendation}")
        print()
else:
    print("Clean — no vulnerable crypto found")
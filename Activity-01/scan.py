from pathlib import Path
import argparse
from collections import defaultdict

def scan_txt_files(directory):
    directory = Path(directory)
    if not directory.exists():
        print("Directory does not exist.")
        return

    # Find all .txt files recursively
    txt_files = list(directory.rglob("*.txt"))

    print(f"\nScanning: {directory.resolve()}")
    print(f"Found {len(txt_files)} text files:\n")

    print(f"{'File':<40} {'Size (KB)':>10}")
    print("-" * 52)

    total_size = 0
    folder_summary = defaultdict(lambda: {'count': 0, 'size': 0})

    # Print files and track summary data
    for file in txt_files:
        size_kb = file.stat().st_size / 1024
        total_size += size_kb
        rel_path = file.relative_to(directory)
        print(f"{str(rel_path):<40} {size_kb:>10.1f}")

        # Group by folder
        folder = str(rel_path.parent) + "/"  # Ensure trailing slash
        folder_summary[folder]['count'] += 1
        folder_summary[folder]['size'] += size_kb

    print("-" * 52)
    print(f"Total size: {total_size:.1f} KB\n")

    # Print folder summary
    print("Summary:")
    for folder, data in sorted(folder_summary.items()):
        print(f"  {folder:<16} —  {data['count']} files, {data['size']:.1f} KB")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recursively scan directory for .txt files.")
    parser.add_argument("path", help="Path to directory to scan")
    args = parser.parse_args()
    scan_txt_files(args.path)

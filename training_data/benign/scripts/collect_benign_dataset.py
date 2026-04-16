#!/usr/bin/env python3
"""
collect_benign_dataset.py  –  Collect diverse real-world benign files for training.

Scans well-known safe directories on the local system to build a representative
benign dataset covering ALL file categories the C++ scanner will encounter:

    PEBinary, Script, WebContent, TextData, Archive, Installer,
    MediaBinary, Unknown

This replaces the synthetic-data approach (generate_synthetic_dataset.py) which
only covered PE executables and text documents, causing the model to treat all
other real-world file types as out-of-distribution anomalies.

Usage:
    python collect_benign_dataset.py --output training_data/benign --max-per-type 500 --dry-run
    python collect_benign_dataset.py --output training_data/benign --max-per-type 500

The output directory is organized by file category for stratified training:
    training_data/benign/
        pe_binary/
        script/
        web_content/
        text_data/
        archive/
        installer/
        media_binary/
        other/
"""

import argparse
import os
import platform
import shutil
import sys
from pathlib import Path
from collections import defaultdict

# ============================================================================
# File category definitions — mirrors FileCategory enum in FileTypeScoring.h
# ============================================================================

CATEGORY_MAP = {
    "pe_binary": {
        "extensions": {"exe", "dll", "sys", "drv", "ocx", "com", "scr", "pif"},
        "description": "PE binaries (Windows executables and libraries)",
    },
    "script": {
        "extensions": {
            "py", "sh", "bash", "ps1", "bat", "cmd", "vbs", "js", "wsh",
            "wsf", "pl", "rb", "php", "lua", "tcl", "zsh", "csh", "fish",
        },
        "description": "Script files (interpreted code)",
    },
    "web_content": {
        "extensions": {"html", "htm", "xhtml", "css", "svg", "xml", "xsl", "json", "jsx", "tsx", "vue"},
        "description": "Web content (HTML, CSS, XML, JSON)",
    },
    "text_data": {
        "extensions": {
            "txt", "md", "rst", "csv", "tsv", "log", "cfg", "conf", "ini",
            "yaml", "yml", "toml", "env", "gitignore", "editorconfig",
            "dockerfile", "makefile", "license", "readme",
        },
        "description": "Text and data files",
    },
    "archive": {
        "extensions": {"zip", "gz", "tar", "bz2", "xz", "7z", "rar", "zst", "lz4"},
        "description": "Compressed archives",
    },
    "installer": {
        "extensions": {"msi", "deb", "rpm", "pkg", "dmg", "appimage", "snap", "flatpak"},
        "description": "Installer packages",
    },
    "media_binary": {
        "extensions": {
            "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "tiff", "tif",
            "mp3", "wav", "flac", "ogg", "aac", "m4a",
            "mp4", "mkv", "avi", "mov", "webm",
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt",
            "ttf", "otf", "woff", "woff2", "eot",
        },
        "description": "Media and binary document files",
    },
    "source_code": {
        # Grouped with text_data for model training — same benign byte patterns
        "extensions": {
            "c", "cpp", "h", "hpp", "java", "cs", "go", "rs", "swift",
            "kt", "scala", "ts", "m", "mm", "r", "jl", "hs", "ml",
        },
        "description": "Source code files (treated as text_data for training)",
    },
}

# Merge source_code into text_data for the actual output directories
# (the model doesn't need a separate category — byte patterns are similar)
TRAINING_CATEGORY_MAP = {
    k: v for k, v in CATEGORY_MAP.items() if k != "source_code"
}
TRAINING_CATEGORY_MAP["text_data"]["extensions"] |= CATEGORY_MAP["source_code"]["extensions"]

# Build reverse lookup: extension -> category
EXT_TO_CATEGORY = {}
for cat, info in TRAINING_CATEGORY_MAP.items():
    for ext in info["extensions"]:
        EXT_TO_CATEGORY[ext] = cat


# ============================================================================
# System directories to scan — OS-aware
# ============================================================================

def get_scan_directories():
    """Return a list of safe, well-known directories to scan for benign files."""
    system = platform.system()
    dirs = []

    if system == "Darwin":  # macOS
        dirs = [
            # System frameworks and libraries (PE-like Mach-O, but features work)
            "/System/Library/Frameworks",
            "/System/Library/PreferencePanes",
            "/Library/Frameworks",
            # Applications
            "/Applications",
            "/System/Applications",
            # Web content / text / config
            "/Library/WebServer/Documents",
            "/etc",
            "/usr/share",
            "/usr/local/share",
            # Homebrew (wide variety of file types)
            "/opt/homebrew",
            "/usr/local/Cellar",
            # User-level (safe system files)
            os.path.expanduser("~/Library/Application Support"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
            # Python/Node packages — great source of diverse scripts
            "/Library/Python",
            "/usr/local/lib/python3",
            "/opt/homebrew/lib/python3",
        ]
    elif system == "Linux":
        dirs = [
            "/usr/bin",
            "/usr/lib",
            "/usr/share",
            "/usr/local/share",
            "/etc",
            "/opt",
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
            "/usr/lib/python3",
            "/usr/local/lib/python3",
            "/var/www",
        ]
    elif system == "Windows":
        dirs = [
            r"C:\Windows\System32",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Downloads"),
            r"C:\Windows\Web",
            r"C:\Python3",
        ]

    return [d for d in dirs if os.path.isdir(d)]


# ============================================================================
# File collection logic
# ============================================================================

# Skip files that might be sensitive, huge, or not useful for training
SKIP_PATTERNS = {
    ".ds_store", "thumbs.db", ".git", "__pycache__", "node_modules",
    ".pyc", ".pyo", ".class", ".o", ".obj", ".a", ".lib",
}

MIN_FILE_SIZE = 256        # Too small = no signal (matches C++ checkByAI)
MAX_FILE_SIZE = 10_000_000  # 10MB cap for training (keep dataset manageable)


def should_skip(path: Path) -> bool:
    """Return True if the file should be excluded from the dataset."""
    name_lower = path.name.lower()

    # Skip hidden files and common non-useful patterns
    if name_lower.startswith("."):
        return True
    for skip in SKIP_PATTERNS:
        if skip in name_lower:
            return True

    # Skip symlinks (avoid duplicates and circular refs)
    if path.is_symlink():
        return True

    return False


def categorize_file(path: Path) -> str:
    """Determine the training category for a file based on extension."""
    ext = path.suffix.lstrip(".").lower()

    # Handle extensionless files
    if not ext:
        name = path.name.lower()
        if name in ("makefile", "dockerfile", "license", "readme", "changelog"):
            return "text_data"
        return "other"

    return EXT_TO_CATEGORY.get(ext, "other")


def scan_for_files(scan_dirs, max_per_type, verbose=False):
    """
    Walk the scan directories and collect files, organized by category.
    Returns dict: category -> list of Path objects.
    """
    collected = defaultdict(list)
    type_counts = defaultdict(int)
    ext_counts = defaultdict(lambda: defaultdict(int))
    skipped = 0
    errors = 0

    # Track which categories still need files
    categories_full = set()

    for scan_dir in scan_dirs:
        if verbose:
            print(f"\n  Scanning: {scan_dir}")

        try:
            for root, dirs, files in os.walk(scan_dir, followlinks=False):
                # Skip hidden directories
                dirs[:] = [d for d in dirs if not d.startswith(".")
                           and d.lower() not in ("node_modules", "__pycache__", ".git")]

                for fname in files:
                    fpath = Path(root) / fname

                    if should_skip(fpath):
                        skipped += 1
                        continue

                    try:
                        size = fpath.stat().st_size
                    except (OSError, PermissionError):
                        errors += 1
                        continue

                    if size < MIN_FILE_SIZE or size > MAX_FILE_SIZE:
                        skipped += 1
                        continue

                    cat = categorize_file(fpath)
                    if cat in categories_full:
                        continue

                    collected[cat].append(fpath)
                    type_counts[cat] += 1
                    ext = fpath.suffix.lstrip(".").lower() or "(none)"
                    ext_counts[cat][ext] += 1

                    if type_counts[cat] >= max_per_type:
                        categories_full.add(cat)
                        if verbose:
                            print(f"    [{cat}] reached {max_per_type} files — skipping rest")

                    # All categories full? Stop early
                    if len(categories_full) >= len(TRAINING_CATEGORY_MAP) + 1:  # +1 for "other"
                        break

                # Propagate early stop
                if len(categories_full) >= len(TRAINING_CATEGORY_MAP) + 1:
                    break

        except PermissionError:
            if verbose:
                print(f"    Permission denied: {scan_dir}")
            errors += 1

    return collected, ext_counts, skipped, errors


# ============================================================================
# Copy files to output directory
# ============================================================================

def copy_files(collected, output_dir, dry_run=False):
    """Copy collected files to the organized output directory."""
    output = Path(output_dir)
    total_copied = 0

    for cat, files in sorted(collected.items()):
        cat_dir = output / cat
        if not dry_run:
            cat_dir.mkdir(parents=True, exist_ok=True)

        for i, fpath in enumerate(files):
            # Use index prefix to avoid name collisions
            safe_name = f"{i:05d}_{fpath.name}"
            dest = cat_dir / safe_name

            if dry_run:
                if i < 3:
                    print(f"    [DRY RUN] {fpath} -> {dest}")
                elif i == 3:
                    print(f"    [DRY RUN] ... and {len(files) - 3} more")
            else:
                try:
                    shutil.copy2(str(fpath), str(dest))
                    total_copied += 1
                except (OSError, PermissionError) as e:
                    print(f"    Warning: couldn't copy {fpath}: {e}")

    return total_copied


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Collect diverse real-world benign files for model training",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Preview what would be collected (no files copied):
    python collect_benign_dataset.py --output training_data/benign --dry-run

    # Collect up to 500 files per category:
    python collect_benign_dataset.py --output training_data/benign --max-per-type 500

    # Add custom directories to scan:
    python collect_benign_dataset.py --output training_data/benign \\
        --extra-dirs /path/to/project1 /path/to/project2
        """,
    )
    parser.add_argument("--output", required=True,
                        help="Output directory for organized benign files")
    parser.add_argument("--max-per-type", type=int, default=500,
                        help="Maximum files per category (default: 500)")
    parser.add_argument("--extra-dirs", nargs="*", default=[],
                        help="Additional directories to scan")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be collected without copying")
    parser.add_argument("--verbose", action="store_true",
                        help="Show detailed progress")
    args = parser.parse_args()

    print("=" * 65)
    print("Odysseus-AI Benign Dataset Collector")
    print("=" * 65)
    print(f"  Platform:       {platform.system()} {platform.machine()}")
    print(f"  Max per type:   {args.max_per_type}")
    print(f"  Output dir:     {args.output}")
    print(f"  Dry run:        {args.dry_run}")

    # Determine scan directories
    scan_dirs = get_scan_directories()
    if args.extra_dirs:
        for d in args.extra_dirs:
            if os.path.isdir(d):
                scan_dirs.append(d)
            else:
                print(f"  Warning: --extra-dir {d} does not exist, skipping")

    print(f"\n  Directories to scan ({len(scan_dirs)}):")
    for d in scan_dirs:
        print(f"    - {d}")

    # Scan
    print(f"\nScanning for benign files...")
    collected, ext_counts, skipped, errors = scan_for_files(
        scan_dirs, args.max_per_type, verbose=args.verbose
    )

    # Report
    total = sum(len(v) for v in collected.values())
    print(f"\n{'=' * 65}")
    print(f"Collection Summary")
    print(f"{'=' * 65}")
    print(f"  Total files found:  {total}")
    print(f"  Skipped:            {skipped}")
    print(f"  Errors:             {errors}")
    print()

    for cat in list(TRAINING_CATEGORY_MAP.keys()) + ["other"]:
        count = len(collected.get(cat, []))
        desc = TRAINING_CATEGORY_MAP.get(cat, {"description": "Uncategorized"})["description"]
        status = "OK" if count >= 50 else "LOW" if count > 0 else "MISSING"
        bar = "#" * min(count // 10, 40)
        print(f"  {cat:15s} [{status:7s}] {count:5d} files  {bar}")

        # Show extension breakdown
        if cat in ext_counts:
            exts = sorted(ext_counts[cat].items(), key=lambda x: -x[1])[:8]
            ext_str = ", ".join(f".{e}({n})" for e, n in exts)
            print(f"  {'':15s}          {ext_str}")

    # Warnings for missing categories
    missing = [cat for cat in TRAINING_CATEGORY_MAP
               if len(collected.get(cat, [])) == 0]
    low = [cat for cat in TRAINING_CATEGORY_MAP
           if 0 < len(collected.get(cat, [])) < 50]

    if missing:
        print(f"\n  WARNING: No files found for: {', '.join(missing)}")
        print(f"  The model will lack training data for these categories.")
        print(f"  Use --extra-dirs to point to directories containing these file types.")

    if low:
        print(f"\n  NOTE: Low sample count (<50) for: {', '.join(low)}")
        print(f"  Consider adding more samples with --extra-dirs.")

    # Copy or dry-run
    if args.dry_run:
        print(f"\n  [DRY RUN] Would copy {total} files to {args.output}/")
        for cat, files in sorted(collected.items()):
            print(f"\n  {cat}/ ({len(files)} files):")
            copy_files({cat: files}, args.output, dry_run=True)
    else:
        print(f"\nCopying {total} files to {args.output}/...")
        copied = copy_files(collected, args.output)
        print(f"  Copied {copied} files successfully.")

        # Write manifest
        manifest_path = Path(args.output) / "MANIFEST.txt"
        with open(manifest_path, "w") as f:
            f.write(f"Odysseus-AI Benign Training Data\n")
            f.write(f"Collected on: {platform.node()}\n")
            f.write(f"Platform: {platform.system()} {platform.machine()}\n\n")
            for cat, files in sorted(collected.items()):
                f.write(f"{cat}: {len(files)} files\n")
                for fpath in files:
                    f.write(f"  {fpath}\n")
        print(f"  Manifest: {manifest_path}")

    print(f"\nNext steps:")
    print(f"  1. Review the collected files for any unexpected content")
    print(f"  2. Run: python generate_dataset.py --benign-dir {args.output} \\")
    print(f"          --malware-dir training_data/malware --output dataset_v2.csv")
    print(f"  3. Train: python train_model.py --dataset dataset_v2.csv")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import hashlib
from pathlib import Path
import argparse
import sys
from typing import Iterable, Optional


def calculate_hash(file_path: Path, algorithm: str = "md5", buffer_size: int = 8192, verbose: bool = False) -> Optional[str]:
    """
    Calculate the hash of a file using the given algorithm.
    Returns the hex digest string, or None on error.
    """
    try:
        hasher = hashlib.new(algorithm)
    except ValueError:
        print(f"Unsupported algorithm: {algorithm}", file=sys.stderr)
        return None

    try:
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(buffer_size), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError as e:
        if verbose:
            print(f"Error reading {file_path}: {e}", file=sys.stderr)
        return None


def _normalize_extensions(exts: Iterable[str]) -> list:
    normalized = []
    for e in exts:
        if not e:
            continue
        if not e.startswith("."):
            e = "." + e
        normalized.append(e)
    return normalized


def check_hashes(directory: str, exts: Iterable[str], algorithm: str = "md5", output_file: Optional[str] = None, buffer_size: int = 8192, verbose: bool = False) -> None:
    """
    Scan directory for files matching extensions and print/write <hash>  <relative-path> lines.
    """
    base_dir = Path(directory)
    if not base_dir.exists():
        print(f"Directory does not exist: {directory}", file=sys.stderr)
        return

    exts = _normalize_extensions(exts)
    results = []

    for ext in exts:
        pattern = f"*{ext}"
        for file_path in base_dir.rglob(pattern):
            if not file_path.is_file():
                continue
            if verbose:
                print(f"Processing: {file_path}", file=sys.stderr)

            hash_val = calculate_hash(file_path, algorithm=algorithm, buffer_size=buffer_size, verbose=verbose)
            if hash_val is None:
                # error already reported by calculate_hash if verbose
                continue

            # Use a path relative to the scanned directory when possible
            try:
                rel = file_path.relative_to(base_dir)
            except Exception:
                rel = file_path
            line = f"{hash_val}  {rel.as_posix()}"
            print(line)
            results.append(line)

    if output_file:
        try:
            # Use surrogateescape to preserve arbitrary bytes in filenames
            with open(output_file, "w", encoding="utf-8", errors="surrogateescape") as f:
                f.write("\n".join(results) + ("\n" if results else ""))
            if verbose:
                print(f"Hashes written to {output_file}", file=sys.stderr)
        except OSError as e:
            print(f"Error writing to {output_file}: {e}", file=sys.stderr)


def verify_hashes(file_path: str, algorithm: str = "md5", buffer_size: int = 8192, verbose: bool = False) -> bool:
    """
    Verifies hashes in a file (like `md5sum -c` behavior).
    Accepts lines in the form:
      <hash><two spaces><filename>
    or
      <hash><one space><filename>
    Filenames may contain spaces. If the filename begins with '*' it indicates binary mode (GNU md5sum).
    Verification is done relative to the directory containing the checksum file.
    Returns True if all files are OK, False if any failed or missing.
    """
    checksum_path = Path(file_path)
    if not checksum_path.exists():
        print(f"Checksum file does not exist: {file_path}", file=sys.stderr)
        return False

    base_dir = checksum_path.parent or Path(".")
    all_ok = True

    try:
        # Use surrogateescape to preserve arbitrary bytes in filenames
        with open(checksum_path, "r", encoding="utf-8", errors="surrogateescape") as f:
            for raw_line in f:
                # Do not strip spaces—filenames may contain spaces. Only remove trailing newline.
                line = raw_line.rstrip("\n")
                if not line:
                    continue

                # Prefer splitting on two spaces (standard md5sum format), fall back to single space.
                if "  " in line:
                    parts = line.split("  ", 1)
                elif " " in line:
                    parts = line.split(" ", 1)
                else:
                    print(f"Invalid line format: {line}")
                    all_ok = False
                    continue

                if len(parts) != 2:
                    print(f"Invalid line format: {line}")
                    all_ok = False
                    continue

                expected_hash, filename = parts
                # Handle common GNU md5sum binary marker where filename begins with '*'
                if filename.startswith("*"):
                    filename = filename[1:]

                # Resolve path relative to the checksum file location
                filepath = base_dir / filename
                if not filepath.exists():
                    print(f"{filename}: NOT FOUND")
                    all_ok = False
                    continue

                actual_hash = calculate_hash(filepath, algorithm=algorithm, buffer_size=buffer_size, verbose=verbose)
                if actual_hash is None:
                    print(f"{filename}: ERROR")
                    all_ok = False
                    continue

                if actual_hash.lower() == expected_hash.lower():
                    print(f"{filename}: OK")
                else:
                    print(f"{filename}: FAILED")
                    all_ok = False
    except OSError as e:
        print(f"Error verifying hashes: {e}", file=sys.stderr)
        return False

    return all_ok


def main():
    parser = argparse.ArgumentParser(description="Compute or verify checksums of files.")
    parser.add_argument("directory", nargs="?", default=".", help="Directory to scan for files when computing checksums.")
    parser.add_argument("-a", "--algorithm", choices=["md5", "sha256"], default="md5", help="Hash algorithm to use.")
    parser.add_argument("-e", "--ext", nargs="+", default=[".iso"], help="File extensions to include (e.g. .iso .img). Extensions may be provided with or without leading dot.")
    parser.add_argument("-o", "--output", help="Write hashes to a file.")
    parser.add_argument("-b", "--buffer-size", type=int, default=8192, help="Read buffer size in bytes.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("-c", "--check", metavar="FILE", help="Verify hashes from a file (like md5sum -c).")

    args = parser.parse_args()

    if args.check:
        ok = verify_hashes(args.check, algorithm=args.algorithm, buffer_size=args.buffer_size, verbose=args.verbose)
        sys.exit(0 if ok else 1)
    else:
        check_hashes(args.directory, args.ext, algorithm=args.algorithm, output_file=args.output, buffer_size=args.buffer_size, verbose=args.verbose)


if __name__ == "__main__":
    main()

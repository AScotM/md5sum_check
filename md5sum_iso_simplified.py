import hashlib
import pathlib

CHUNK_SIZE = 8192

def calculate_md5(file_path: pathlib.Path):
    """Calculate MD5 checksum for a given file. Returns hexdigest or None on error."""
    md5 = hashlib.md5()
    try:
        with file_path.open('rb') as f:
            while chunk := f.read(CHUNK_SIZE):
                md5.update(chunk)
        return md5.hexdigest()
    except OSError:
        return None

def check_md5sums(directory='.'):
    """Scan a directory for `.iso` files and print their MD5 hashes."""
    dir_path = pathlib.Path(directory)

    if not dir_path.is_dir():
        print(f"Invalid directory: {directory}")
        return

    for file in sorted(dir_path.iterdir()):
        if file.is_file() and file.suffix.lower() == '.iso':
            md5_hash = calculate_md5(file)
            if md5_hash is None:
                print(f"{file.name:40} Error reading file")
            else:
                print(f"{file.name:40} MD5: {md5_hash}")

if __name__ == "__main__":
    check_md5sums(".")

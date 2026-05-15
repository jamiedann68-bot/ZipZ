#!/usr/bin/env python3
import os
import tarfile
import argparse
import zstandard as zstd
import sys
import fnmatch
import stat
import math
import hashlib
import getpass
import subprocess
from pathlib import Path
from datetime import datetime

# Encryption imports
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ZipZ Branding & Custom Format
EXTENSION = ".zz"
IGNORE_FILE = ".zipzignore"
ENC_MAGIC = b"ZIPZ_ENC"
SALT_SIZE = 16
NONCE_SIZE = 12
CHUNK_SIZE = 64 * 1024  # 64KB chunks for encryption

def format_size(size_bytes):
    """Formats bytes into human-readable strings."""
    if size_bytes == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

def get_sha256(file_path):
    """Calculates SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def derive_key(password, salt):
    """Derives a 256-bit key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def push_to_remote(local_path, remote_dest):
    """Pushes a file to a remote destination using rclone."""
    print(f"☁️ Syncing {local_path.name} to {remote_dest}...")
    try:
        rclone_bin = "rclone"
        local_bin = Path(__file__).parent / "bin" / "rclone"
        if local_bin.exists():
            rclone_bin = str(local_bin)
        result = subprocess.run([rclone_bin, "copy", str(local_path), remote_dest], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Sync complete: {local_path.name}")
        else:
            print(f"❌ Sync failed: {result.stderr}")
    except Exception as e:
        print(f"❌ Sync error for {local_path.name}: {e}")

def compress(source, output=None, level=3, exclude=None, threads=0, password=None, remote=None):
    """
    Compress a file or directory into a ZipZ (.zz) archive.
    """
    source_path = Path(source).absolute()
    if not source_path.exists() and not source_path.is_symlink():
        print(f"❌ Error: Source {source} does not exist.")
        sys.exit(1)

    if exclude is None: exclude = []
    ignore_path = source_path / IGNORE_FILE if source_path.is_dir() else source_path.parent / IGNORE_FILE
    if ignore_path.exists():
        print(f"📄 Loading patterns from {ignore_path.name}...")
        with open(ignore_path, "r") as f:
            exclude.extend([line.strip() for line in f if line.strip() and not line.startswith("#")])

    if output is None:
        output = source_path.name
    if not output.endswith(EXTENSION):
        output += EXTENSION
    
    print(f"📦 Zipping {source_path.name} into {output}...")
    
    def tar_filter(tarinfo):
        if not exclude: return tarinfo
        
        path_segments = tarinfo.name.split('/')
        for pattern in exclude:
            clean_p = pattern.rstrip('/')
            for segment in path_segments:
                if fnmatch.fnmatch(segment, clean_p):
                    return None
        return tarinfo

    cctx = zstd.ZstdCompressor(level=level, threads=threads)
    
    try:
        with open(output, 'wb') as f_out:
            dest_file = f_out
            if password:
                salt = os.urandom(SALT_SIZE)
                f_out.write(ENC_MAGIC); f_out.write(salt)
                key = derive_key(password, salt); aesgcm = AESGCM(key)
                class EncryptorWrapper:
                    def __init__(self, target): self.target = target
                    def write(self, data):
                        for i in range(0, len(data), CHUNK_SIZE):
                            chunk = data[i:i+CHUNK_SIZE]
                            nonce = os.urandom(NONCE_SIZE)
                            encrypted = aesgcm.encrypt(nonce, chunk, None)
                            self.target.write(nonce)
                            self.target.write(len(encrypted).to_bytes(4, 'big'))
                            self.target.write(encrypted)
                    def flush(self): self.target.flush()
                    def close(self): pass
                dest_file = EncryptorWrapper(f_out)

            with cctx.stream_writer(dest_file) as compressor:
                with tarfile.open(fileobj=compressor, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                    tar.add(str(source_path), arcname=source_path.name, filter=tar_filter)
        
        # Hash sidecar
        hash_file_path = Path(output + ".sha256")
        file_hash = get_sha256(output)
        with open(hash_file_path, "w") as f:
            f.write(f"{file_hash}  {os.path.basename(output)}\n")
        
        print(f"✅ Successfully created {output}")
        if remote:
            push_to_remote(Path(output), remote); push_to_remote(hash_file_path, remote)

    except Exception as e:
        print(f"❌ Error during compression: {e}")
        if os.path.exists(output): os.remove(output)
        sys.exit(1)

def resolve_archive_path(archive):
    path = Path(archive).resolve()
    if (path.is_dir() or not path.exists()) and not archive.endswith(EXTENSION):
        alt_path = Path(archive + EXTENSION).resolve()
        if alt_path.exists() and alt_path.is_file(): return alt_path
    return path

def decompress(archive, output_dir, password=None):
    archive_path = resolve_archive_path(archive)
    if not archive_path.exists() or not archive_path.is_file():
        print(f"❌ Error: Archive {archive} does not exist."); sys.exit(1)

    with open(archive_path, 'rb') as f_in:
        magic = f_in.read(len(ENC_MAGIC)); is_encrypted = (magic == ENC_MAGIC)
        if is_encrypted:
            if not password: password = getpass.getpass("🔑 Enter password for decryption: ")
            salt = f_in.read(SALT_SIZE); key = derive_key(password, salt); aesgcm = AESGCM(key)
            class DecryptorWrapper:
                def __init__(self, source): self.source = source; self.buffer = b""
                def read(self, size):
                    while len(self.buffer) < size:
                        nonce = self.source.read(NONCE_SIZE)
                        if not nonce: break
                        len_bytes = self.source.read(4)
                        if not len_bytes: break
                        chunk_len = int.from_bytes(len_bytes, 'big')
                        encrypted = self.source.read(chunk_len)
                        try: self.buffer += aesgcm.decrypt(nonce, encrypted, None)
                        except: print("❌ Error: Decryption failed."); sys.exit(1)
                    res = self.buffer[:size]; self.buffer = self.buffer[size:]; return res
            input_stream = DecryptorWrapper(f_in)
        else:
            f_in.seek(0); input_stream = f_in

        output_path = Path(output_dir).resolve()
        output_path.mkdir(parents=True, exist_ok=True)
        print(f"🔓 Unzipping {archive_path.name} to {output_path}...")
        dctx = zstd.ZstdDecompressor()
        try:
            with dctx.stream_reader(input_stream) as reader:
                with tarfile.open(fileobj=reader, mode='r|') as tar:
                    tar.extractall(path=str(output_path))
            print(f"✅ Successfully extracted to {output_dir}")
        except Exception as e:
            print(f"❌ Error during decompression: {e}"); sys.exit(1)

def list_content(archive, password=None):
    archive_path = resolve_archive_path(archive)
    if not archive_path.exists() or not archive_path.is_file():
        print(f"❌ Error: Archive {archive} does not exist."); sys.exit(1)

    with open(archive_path, 'rb') as f_in:
        magic = f_in.read(len(ENC_MAGIC)); is_encrypted = (magic == ENC_MAGIC)
        if is_encrypted:
            if not password: password = getpass.getpass("🔑 Enter password for listing: ")
            salt = f_in.read(SALT_SIZE); key = derive_key(password, salt); aesgcm = AESGCM(key)
            class DecryptorWrapper:
                def __init__(self, source): self.source = source; self.buffer = b""
                def read(self, size):
                    while len(self.buffer) < size:
                        nonce = self.source.read(NONCE_SIZE)
                        if not nonce: break
                        len_bytes = self.source.read(4)
                        if not len_bytes: break
                        chunk_len = int.from_bytes(len_bytes, 'big')
                        encrypted = self.source.read(chunk_len)
                        try: self.buffer += aesgcm.decrypt(nonce, encrypted, None)
                        except: print("❌ Error: Decryption failed."); sys.exit(1)
                    res = self.buffer[:size]; self.buffer = self.buffer[size:]; return res
            input_stream = DecryptorWrapper(f_in)
        else:
            f_in.seek(0); input_stream = f_in

        print(f"📜 Listing contents of {archive_path.name}:")
        print("-" * 85); print(f"{'Mode':<12} {'Size':>12} {'Modified':<20} {'Name'}"); print("-" * 85)
        dctx = zstd.ZstdDecompressor()
        try:
            with dctx.stream_reader(input_stream) as reader:
                with tarfile.open(fileobj=reader, mode='r|') as tar:
                    for member in tar:
                        mode = stat.filemode(member.mode); size = format_size(member.size)
                        mtime = datetime.fromtimestamp(member.mtime).strftime('%Y-%m-%d %H:%M:%S')
                        name = member.name + ("/" if member.isdir() else "")
                        print(f"{mode:<12} {size:>12} {mtime:<20} {name}")
        except Exception as e:
            print(f"❌ Error during listing: {e}"); sys.exit(1)

def verify(archive, password=None):
    archive_path = resolve_archive_path(archive)
    if not archive_path.exists():
        print(f"❌ Error: Archive {archive} does not exist."); sys.exit(1)
    print(f"🔍 Verifying {archive_path.name}...")
    hash_file = Path(str(archive_path) + ".sha256")
    if hash_file.exists():
        current_hash = get_sha256(archive_path)
        with open(hash_file, "r") as f: expected_hash = f.read().split()[0]
        if current_hash == expected_hash: print("✅ SHA-256 hash matches.")
        else: print(f"❌ SHA-256 hash MISMATCH!"); sys.exit(1)
    else: print("⚠️ No SHA-256 sidecar found.")

def main():
    parser = argparse.ArgumentParser(description="ZipZ - The efficient, easy-to-remember Zstandard archiver.")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    c_parser = subparsers.add_parser("compress")
    c_parser.add_argument("source")
    c_parser.add_argument("-o", "--output")
    c_parser.add_argument("-l", "--level", type=int, default=3)
    c_parser.add_argument("-e", "--exclude", nargs="+")
    c_parser.add_argument("-j", "--threads", type=int, default=0)
    c_parser.add_argument("-p", "--password", nargs='?', const=True)
    c_parser.add_argument("-r", "--remote")

    d_parser = subparsers.add_parser("decompress")
    d_parser.add_argument("archive"); d_parser.add_argument("-o", "--output", required=True); d_parser.add_argument("-p", "--password")

    l_parser = subparsers.add_parser("list")
    l_parser.add_argument("archive"); l_parser.add_argument("-p", "--password")

    v_parser = subparsers.add_parser("verify")
    v_parser.add_argument("archive"); v_parser.add_argument("-p", "--password")

    args = parser.parse_args(); pwd = args.password
    if pwd is True:
        pwd = getpass.getpass("🔐 Enter password: "); cpwd = getpass.getpass("🔐 Confirm: ")
        if pwd != cpwd: print("❌ Passwords mismatch."); sys.exit(1)

    if args.command == "compress": compress(args.source, args.output, args.level, args.exclude, args.threads, pwd, args.remote)
    elif args.command == "decompress": decompress(args.archive, args.output, pwd)
    elif args.command == "list": list_content(args.archive, pwd)
    elif args.command == "verify": verify(args.archive, pwd)
    else: parser.print_help()

if __name__ == "__main__": main()

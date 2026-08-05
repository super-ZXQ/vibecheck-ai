"""Pytest fixtures and helpers for VibeCheck tests.

IMPORTANT: All test strings used to simulate secrets/keys are SYNTHETIC.
They have the correct format but NO actual permissions or validity.
No real credentials are used in any test.
"""

import io
import tarfile
import tempfile
from pathlib import Path

import pytest


# --- Synthetic test constants ---
# These strings have the correct FORMAT but are NOT real, valid credentials.
# Runtime-constructed mixed-character values to avoid low-entropy patterns.
_MIXED = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB1cD2eF3gH4"
_MIXED_UPPER = "ABCDEF1234567890GHIJKLMNOP"
SYNTHETIC_GITHUB_TOKEN = "ghp_" + _MIXED[:36]  # Format-correct, not a real token
SYNTHETIC_AWS_KEY = "AKIA" + _MIXED_UPPER[:16]  # Format-correct, not a real key
SYNTHETIC_GOOGLE_KEY = "AIza" + _MIXED[:35]  # Format-correct, not a real key
SYNTHETIC_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA" + "D" * 400 + "\n"
    "-----END RSA PRIVATE KEY-----"
)
SYNTHETIC_PASSWORD = 'DB_PASSWORD="s3cur3P@ssw0rd123!"'


# --- Tarball creation helpers ---

def make_normal_tarball() -> bytes:
    """Create a normal, safe tarball with a few files."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Top-level directory
        dir_info = tarfile.TarInfo(name="test-repo/")
        dir_info.type = tarfile.DIRTYPE
        dir_info.mode = 0o755
        tar.addfile(dir_info)

        # README file
        readme_content = b"# Test Repo\n\nThis is a test repository.\n"
        readme_info = tarfile.TarInfo(name="test-repo/README.md")
        readme_info.size = len(readme_content)
        readme_info.mode = 0o644
        tar.addfile(readme_info, io.BytesIO(readme_content))

        # Source file
        src_content = b'print("hello world")\n'
        src_info = tarfile.TarInfo(name="test-repo/main.py")
        src_info.size = len(src_content)
        src_info.mode = 0o644
        tar.addfile(src_info, io.BytesIO(src_content))

    return buf.getvalue()


def make_traversal_tarball() -> bytes:
    """Create a tarball with path traversal entries."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Normal file first
        content = b"safe\n"
        info = tarfile.TarInfo(name="safe.txt")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))

        # Path traversal entry
        evil_content = b"hacked\n"
        evil_info = tarfile.TarInfo(name="../../etc/passwd")
        evil_info.size = len(evil_content)
        evil_info.mode = 0o644
        tar.addfile(evil_info, io.BytesIO(evil_content))

    return buf.getvalue()


def make_symlink_tarball() -> bytes:
    """Create a tarball with a symlink entry."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Normal file
        content = b"safe\n"
        info = tarfile.TarInfo(name="safe.txt")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))

        # Symlink
        sym_info = tarfile.TarInfo(name="evil_link")
        sym_info.type = tarfile.SYMTYPE
        sym_info.linkname = "/etc/passwd"
        sym_info.mode = 0o777
        tar.addfile(sym_info)

    return buf.getvalue()


def make_hardlink_tarball() -> bytes:
    """Create a tarball with a hardlink entry."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Normal file
        content = b"safe\n"
        info = tarfile.TarInfo(name="safe.txt")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))

        # Hardlink
        lnk_info = tarfile.TarInfo(name="evil_hardlink")
        lnk_info.type = tarfile.LNKTYPE
        lnk_info.linkname = "safe.txt"
        lnk_info.mode = 0o644
        tar.addfile(lnk_info)

    return buf.getvalue()


def make_device_tarball() -> bytes:
    """Create a tarball with device file entries."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Normal file
        content = b"safe\n"
        info = tarfile.TarInfo(name="safe.txt")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))

        # Character device
        chr_info = tarfile.TarInfo(name="evil_char_dev")
        chr_info.type = tarfile.CHRTYPE
        chr_info.devmajor = 1
        chr_info.devminor = 3
        chr_info.mode = 0o666
        tar.addfile(chr_info)

        # Block device
        blk_info = tarfile.TarInfo(name="evil_blk_dev")
        blk_info.type = tarfile.BLKTYPE
        blk_info.devmajor = 8
        blk_info.devminor = 0
        blk_info.mode = 0o660
        tar.addfile(blk_info)

    return buf.getvalue()


def make_fifo_tarball() -> bytes:
    """Create a tarball with a FIFO entry."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Normal file
        content = b"safe\n"
        info = tarfile.TarInfo(name="safe.txt")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))

        # FIFO
        fifo_info = tarfile.TarInfo(name="evil_fifo")
        fifo_info.type = tarfile.FIFOTYPE
        fifo_info.mode = 0o600
        tar.addfile(fifo_info)

    return buf.getvalue()


def make_oversized_tarball(file_size: int) -> bytes:
    """Create a tarball with a single file of the given size."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        content = b"\x00" * file_size
        info = tarfile.TarInfo(name="big_file.bin")
        info.size = file_size
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def make_many_files_tarball(count: int) -> bytes:
    """Create a tarball with the given number of small files."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        content = b"x"
        for i in range(count):
            info = tarfile.TarInfo(name=f"file_{i}.txt")
            info.size = 1
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def make_absolute_path_tarball() -> bytes:
    """Create a tarball with an absolute path entry."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        content = b"evil\n"
        info = tarfile.TarInfo(name="/etc/evil")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def make_null_byte_tarball() -> bytes:
    """Create a tarball with a null byte in the filename."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        content = b"evil\n"
        info = tarfile.TarInfo(name="safe\x00evil.txt")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


@pytest.fixture
def tmp_dest_dir():
    """Create a temporary directory for extraction tests."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)

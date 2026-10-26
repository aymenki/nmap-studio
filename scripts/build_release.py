"""Build a reproducible source archive and SHA-256 checksum."""
from __future__ import annotations

import hashlib
import pathlib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION = "0.4.2"
OUTPUT_DIR = ROOT / "release"
ARCHIVE = OUTPUT_DIR / f"nmap-studio-v{VERSION}.zip"
INCLUDE = [
    "dist",
    "docs",
    "server.py",
    "workspace.py",
    "intelligence.py",
    "launch.py",
    "start.cmd",
    "stop.cmd",
    "README.md",
    "LICENSE",
    "NMAP-LICENSE.txt",
    "THIRD_PARTY_NOTICES.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
]


def files():
    for name in INCLUDE:
        path = ROOT / name
        if path.is_dir():
            yield from sorted(item for item in path.rglob("*") if item.is_file())
        elif path.is_file():
            yield path


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)
    with zipfile.ZipFile(ARCHIVE, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files():
            info = zipfile.ZipInfo.from_file(path, path.relative_to(ROOT).as_posix())
            info.date_time = (2026, 10, 26, 0, 0, 0)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    digest = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()
    checksum = ARCHIVE.with_suffix(ARCHIVE.suffix + ".sha256")
    checksum.write_text(f"{digest}  {ARCHIVE.name}\n", encoding="ascii")
    print(ARCHIVE)
    print(checksum)


if __name__ == "__main__":
    main()

"""Reusable test fixtures, payload generators, and mock artifact builders for E2E tests."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
from typing import Any
import zlib


class E2EFixtures:
    """Factory for multi-domain test artifacts, binaries, and directory structures."""

    @staticmethod
    def create_temp_dir(prefix: str = "e2e_") -> Path:
        """Create a temporary directory for hermetic test execution."""
        return Path(tempfile.mkdtemp(prefix=prefix))

    @staticmethod
    def cleanup_dir(dir_path: Path) -> None:
        """Safely remove a temporary directory."""
        if dir_path.exists():
            shutil.rmtree(dir_path, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Binary Artifacts (ELF, PE, Mach-O, UEFI, SquashFS)
    # -------------------------------------------------------------------------

    @staticmethod
    def sample_elf_x86_64(with_checksec: bool = True) -> bytes:
        """Generate a valid 64-bit ELF header with optional checksec mitigation markers."""
        header = bytearray(
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00"
        )
        if with_checksec:
            header.extend(b"GNU_STACK\x00__stack_chk_fail\x00_chk\x00")
            header.extend(b"\x00" * 32)
        return bytes(header)

    @staticmethod
    def sample_elf_arm64() -> bytes:
        """Generate a valid 64-bit ARM64 ELF header."""
        return bytes(
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00"
            + b"\x00" * 16
        )

    @staticmethod
    def sample_elf_mips() -> bytes:
        """Generate a valid 32-bit MIPS ELF header."""
        return bytes(
            b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x08\x00"
            + b"\x00" * 16
        )

    @staticmethod
    def sample_pe() -> bytes:
        """Generate a valid PE (MZ header) byte sequence."""
        return bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 32)

    @staticmethod
    def sample_macho() -> bytes:
        """Generate a valid 64-bit Mach-O byte sequence."""
        return bytes(
            b"\xcf\xfa\xed\xfe\x07\x00\x00\x01\x03\x00\x00\x00\x02\x00\x00\x00"
            + b"\x00" * 16
        )

    @staticmethod
    def sample_uefi_fvh() -> bytes:
        """Generate a UEFI Firmware Volume Header byte sequence."""
        return bytes(b"\x00" * 32 + b"_FVH" + b"\x00" * 92)

    @staticmethod
    def sample_squashfs(high_entropy_suffix: bool = False) -> bytes:
        """Generate a SquashFS header with optional pseudorandom payload."""
        base = bytearray(b"hsqs")
        if high_entropy_suffix:
            # 60 pseudo-random bytes with high entropy
            base.extend(bytes((i * 101 + 37) % 256 for i in range(60)))
        else:
            base.extend(b"\x00" * 28)
        return bytes(base)

    @staticmethod
    def sample_xz() -> bytes:
        """Generate an XZ/LZMA container header."""
        return bytes(b"\xfd7zXZ\x00" + b"\x00" * 26)

    # -------------------------------------------------------------------------
    # Dependency & Vulnerability Manifests
    # -------------------------------------------------------------------------

    @staticmethod
    def setup_project_dependencies(
        dest_dir: Path,
        variant: str = "vulnerable",
    ) -> Path:
        """Create package manifests in the target directory."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        if variant == "vulnerable":
            (dest_dir / "requirements.txt").write_text(
                "demo-parser==1.2.0\nrequests==2.25.1\n",
                encoding="utf-8",
            )
        elif variant == "clean":
            (dest_dir / "requirements.txt").write_text(
                "demo-parser==1.4.1\nrequests==2.31.0\n",
                encoding="utf-8",
            )
        elif variant == "unpinned":
            (dest_dir / "requirements.txt").write_text(
                "unpinned-pkg\n",
                encoding="utf-8",
            )
        elif variant == "polyglot":
            (dest_dir / "requirements.txt").write_text("demo-parser==1.2.0\n", encoding="utf-8")
            (dest_dir / "pyproject.toml").write_text(
                '[project]\ndependencies = ["requests>=2.25.0"]\n',
                encoding="utf-8",
            )
            (dest_dir / "package-lock.json").write_text(
                json.dumps(
                    {
                        "name": "polyglot-app",
                        "version": "1.0.0",
                        "lockfileVersion": 2,
                        "packages": {
                            "": {"name": "polyglot-app"},
                            "node_modules/lodash": {"version": "4.17.20"},
                        },
                    }
                ),
                encoding="utf-8",
            )
        return dest_dir

    # -------------------------------------------------------------------------
    # Forensics & STIX Artifacts
    # -------------------------------------------------------------------------

    @staticmethod
    def sample_stix2_bundle(
        indicator_value: str = "malicious-c2.net",
        threat_family: str = "Predator",
    ) -> dict[str, Any]:
        """Generate a valid STIX 2.1 indicator bundle."""
        return {
            "type": "bundle",
            "id": "bundle--11111111-2222-3333-4444-555555555555",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    "spec_version": "2.1",
                    "pattern_type": "stix",
                    "pattern": f"[domain-name:value = '{indicator_value}']",
                    "name": f"{threat_family} C2 domain",
                    "x_threat_family": threat_family,
                    "labels": [threat_family.lower()],
                    "external_references": [
                        {
                            "source_name": "threat_intel",
                            "external_id": f"IOC-{threat_family}-001",
                        }
                    ],
                }
            ],
        }

    @staticmethod
    def setup_forensics_bundle(
        dest_dir: Path,
        platform: str = "ios",
        variant: str = "clean",
    ) -> Path:
        """Create mock device backup / artifact files in the target directory."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        if platform == "ios":
            if variant == "clean":
                (dest_dir / "Shutdown.log").write_text(
                    "2026-10-01T08:00:00Z SIGTERM SpringBoard MobileSafari\n",
                    encoding="utf-8",
                )
            elif variant == "infected":
                (dest_dir / "Shutdown.log").write_text(
                    "2026-09-12T04:11:00Z SIGTERM process roleaboutd\n",
                    encoding="utf-8",
                )
            elif variant == "encrypted":
                (dest_dir / "Manifest.plist").write_text(
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<plist version="1.0">\n<dict>\n'
                    "<key>IsEncrypted</key>\n<true/>\n"
                    "</dict>\n</plist>\n",
                    encoding="utf-8",
                )
            elif variant == "corrupt_db":
                (dest_dir / "sms.db").write_bytes(b"CORRUPT_NON_SQLITE_GARBAGE_BYTES_1234")
        elif platform == "android":
            if variant == "clean":
                (dest_dir / "packages.list").write_text(
                    "com.android.chrome 10045 0 /data/data/com.android.chrome default:targetSdkVersion=34\n",
                    encoding="utf-8",
                )
            elif variant == "infected":
                (dest_dir / "packages.list").write_text(
                    "com.cytrox.alien.agent 10099 0 /data/data/com.cytrox.alien.agent default:targetSdkVersion=30\n",
                    encoding="utf-8",
                )
        elif platform == "host":
            if variant == "clean":
                (dest_dir / "auth.log").write_text(
                    "Accepted publickey for admin from 10.0.0.1 port 52312 ssh2\n",
                    encoding="utf-8",
                )
            elif variant == "anomaly":
                (dest_dir / "cron.log").write_text(
                    "CRON[1234]: (root) CMD (/private/var/tmp/unknown_script.sh)\n",
                    encoding="utf-8",
                )
        return dest_dir

    # -------------------------------------------------------------------------
    # Vulnerability Code Payloads (CPG Sinks)
    # -------------------------------------------------------------------------

    @staticmethod
    def sample_cwe_source(cwe_id: str) -> str:
        """Return canonical source code exercising a specific CWE class."""
        mapping = {
            "CWE-78": (
                "import subprocess\n"
                "def ping(host):\n"
                "    cmd = host\n"
                "    return subprocess.run(cmd, shell=True)\n"
            ),
            "CWE-89": (
                "def get_user(cursor, user_id):\n"
                "    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
            ),
            "CWE-94": (
                "def execute(user_code):\n"
                "    return eval(user_code)\n"
            ),
            "CWE-502": (
                "import pickle\n"
                "def load(data):\n"
                "    return pickle.loads(data)\n"
            ),
            "CWE-120": (
                "void copy(char *src) {\n"
                "    char dest[64];\n"
                "    strcpy(dest, src);\n"
                "}\n"
            ),
            "CWE-22": (
                "import tarfile\n"
                "def extract(tar_path):\n"
                "    tarfile.extractall(tar_path)\n"
            ),
            "CWE-327": (
                "import hashlib\n"
                "def hash_val(data):\n"
                "    return hashlib.md5(data).hexdigest()\n"
            ),
            "CWE-611": (
                "import xml.etree.ElementTree as ET\n"
                "def parse(data):\n"
                "    return ET.fromstring(data)\n"
            ),
            "CWE-798": (
                "API_KEY = 'AKIA1234567890ABCDEF12'\n"
            ),
            "CWE-918": (
                "import requests\n"
                "def fetch(endpoint):\n"
                "    return requests.get(endpoint)\n"
            ),
        }
        return mapping.get(cwe_id, "def safe(): return 42\n")

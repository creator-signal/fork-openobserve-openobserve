"""Verify that compatibility manifests select exact fixed upstream source."""
import hashlib
import json
from pathlib import Path
import tomllib

root = Path(__file__).resolve().parents[2]
for name, upstream, compatibility in [
    ("zstd", "0.14.3", "0.13.4"),
    ("zstd-safe", "8.2.0", "7.2.5"),
]:
    record = json.loads((root / "vendor" / f"{name}-import.json").read_text())
    directory = root / "vendor" / f"{name}-compat"
    expected = {entry["path"]: entry["sha256"] for entry in record["files"]}
    for filename, digest in expected.items():
        data = (directory / filename).read_bytes()
        if filename == "Cargo.toml":
            text = data.decode()
            suffix = "\n[workspace]\n"
            if name == "zstd":
                suffix += '\n[patch.crates-io]\nzstd-safe = { path = "../zstd-safe-compat" }\n'
            assert text.endswith(suffix)
            text = text[:-len(suffix)].replace(f'version = "{compatibility}"', f'version = "{upstream}"', 1)
            if name == "zstd":
                text = text.replace('[dependencies.zstd-safe]\nversion = "7.2.5"', '[dependencies.zstd-safe]\nversion = "8.2.0"')
            data = text.encode()
        assert hashlib.sha256(data).hexdigest() == digest, f"unexpected upstream drift: {name}/{filename}"
    manifest = tomllib.loads((directory / "Cargo.toml").read_text())
    assert manifest["package"]["version"] == compatibility
    for asset in record.get("testAssets", []):
        assert hashlib.sha256((directory / asset["path"]).read_bytes()).hexdigest() == asset["sha256"]

lock = tomllib.loads((root / "Cargo.lock").read_text())
for package in lock["package"]:
    assert not (package["name"] == "zstd" and package["version"] == "0.13.3")
    assert not (package["name"] == "zstd-safe" and package["version"] == "7.2.4")
print("Verified fixed upstream Zstandard sources, compatibility-only manifests and closed vulnerable lockfile versions")

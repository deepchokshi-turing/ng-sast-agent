"""The claude_review pins, installer, tools image part and scoped texts.

The pinned upstream hashes are checked against the vendored copy of the
upstream files at 0c6a49f (tests/fixtures/ccsr_0c6a49f, copied unedited from
a clean checkout of that commit). The installer runs against a local HTTP
server with a stand-in npm tarball, so nothing is downloaded from the internet
and the real Claude Code binary is not needed.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import importlib.util
import io
import json
import platform
import re
import tarfile
import threading
from pathlib import Path

import pytest

from sast import manifest
from sast.claude_review import install, pins
from tests.claude_review_fakes import CCSR_DIR
from tests.conftest import FIXTURES, ROOT, SAMPLE_TASKS

HERE = ROOT / "sast" / "claude_review"


# ---------------------------------------------------------------- pins


def test_pinned_upstream_hashes_match_the_vendored_commit():
    for rel, expected in pins.CCSR_FILES.items():
        assert hashlib.sha256((CCSR_DIR / rel).read_bytes()).hexdigest() == expected, rel
    assert pins.CCSR_COMMIT.startswith("0c6a49f") and len(pins.CCSR_COMMIT) == 40
    assert pins.CCSR_RAW_URL.format(path="claudecode/prompts.py") == (
        "https://raw.githubusercontent.com/anthropics/claude-code-security-review/"
        "0c6a49f1fa56a1d472575da86a94dbc1edb78eda/claudecode/prompts.py")


def test_upstream_default_model_is_the_one_in_constants():
    text = (CCSR_DIR / "claudecode" / "constants.py").read_text()
    assert f"DEFAULT_CLAUDE_MODEL = os.environ.get('CLAUDE_MODEL') or '{pins.UPSTREAM_DEFAULT_MODEL}'" in text
    # The filter's API check model that the driver replaces.
    assert 'model="claude-3-5-haiku-20241022"' in (CCSR_DIR / "claudecode" / "claude_api_client.py").read_text()


def test_requirements_are_hash_pinned_and_match_the_pins():
    data = (HERE / pins.REQUIREMENTS_FILE).read_bytes()
    assert hashlib.sha256(data).hexdigest() == pins.REQUIREMENTS_SHA256
    text = data.decode()
    requirements = re.findall(r"^([a-z0-9-]+)==(\S+)", text, re.MULTILINE)
    assert ("anthropic", pins.ANTHROPIC_VERSION) in requirements and ("requests", pins.REQUESTS_VERSION) in requirements
    blocks = re.split(r"\n(?=[a-z])", text.split("\n\n")[-1] if "\n\n" in text else text)
    for block in (b for b in blocks if re.match(r"^[a-z0-9-]+==", b)):
        assert "--hash=sha256:" in block, block.splitlines()[0]


def test_claude_code_packages_are_npm_platform_tarballs():
    assert set(pins.CLAUDE_CODE_PACKAGES) == {"x86_64", "aarch64"}
    for arch, (package, sha, integrity) in pins.CLAUDE_CODE_PACKAGES.items():
        assert re.fullmatch(r"[0-9a-f]{64}", sha) and integrity.startswith("sha512-")
        assert len(base64.b64decode(integrity[len("sha512-"):])) == 64
        assert pins.claude_code_tarball_url(arch) == (
            f"https://registry.npmjs.org/{package}/-/{package.split('/')[1]}-{pins.CLAUDE_CODE_VERSION}.tgz")
    assert pins.as_dict()["claude_code_version"] == pins.CLAUDE_CODE_VERSION


# ---------------------------------------------------------------- installer checks


def _exe(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


def fake_part(root: Path, version=pins.CLAUDE_CODE_VERSION, anthropic=pins.ANTHROPIC_VERSION) -> Path:
    """A part with a stand-in claude, the vendored upstream files and a stand-in venv Python."""
    _exe(root / "bin" / "claude", f'#!/bin/sh\necho "{version} (Claude Code)"\n')
    for rel in pins.CCSR_FILES:
        target = root / "ccsr" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((CCSR_DIR / rel).read_bytes())
    probe = json.dumps({"python": "3.12.11", "anthropic": anthropic, "requests": pins.REQUESTS_VERSION})
    _exe(root / "venv" / "bin" / "python", f"#!/bin/sh\necho '{probe}'\n")
    return root


def test_check_part_accepts_a_matching_part(tmp_path):
    part = fake_part(tmp_path / "claude-review")
    result = install.check_part(str(part), pins.as_dict(), str(tmp_path))
    assert result["claude_version_output"] == f"{pins.CLAUDE_CODE_VERSION} (Claude Code)"
    assert result["ccsr_files"] == len(pins.CCSR_FILES) and result["anthropic"] == pins.ANTHROPIC_VERSION
    assert result["venv_python"].endswith("/venv/bin/python")


@pytest.mark.parametrize("damage, message", [
    (lambda p: fake_part(p, version="2.0.0"), "expected 2.1.296"),
    (lambda p: (p / "ccsr" / "claudecode" / "prompts.py").write_text("# changed\n"), "prompts.py has sha256"),
    (lambda p: (p / "ccsr" / "claudecode" / "constants.py").unlink(), "constants.py is missing"),
    (lambda p: fake_part(p, anthropic="0.39.0"), "the venv has anthropic 0.39.0"),
    (lambda p: (p / "bin" / "claude").unlink(), "no executable"),
])
def test_check_part_refuses_anything_else(tmp_path, damage, message):
    part = fake_part(tmp_path / "claude-review")
    damage(part)
    with pytest.raises(install.InstallError, match=message):
        install.check_part(str(part), pins.as_dict(), str(tmp_path))


@pytest.mark.parametrize("probe", ["", "not json", "[1, 2]"])
def test_a_venv_probe_without_json_is_an_install_error(tmp_path, probe):
    part = fake_part(tmp_path / "claude-review")
    _exe(part / "venv" / "bin" / "python", f"#!/bin/sh\necho '{probe}'\n")
    with pytest.raises(install.InstallError, match="printed no JSON result"):
        install.check_part(str(part), pins.as_dict(), str(tmp_path))


def test_probes_inherit_no_host_claude_settings(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "/x")
    env = install.quiet_env("/h")
    assert "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST" not in env and "ANTHROPIC_API_KEY" not in env
    assert "CLAUDE_CONFIG_DIR" not in env and env["HOME"] == "/h" and "PATH" in env


class Server:
    """Serves ``files`` ({url path: bytes}) on 127.0.0.1."""

    def __init__(self, files):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                data = files.get(self.path)
                self.send_response(200 if data is not None else 404)
                self.end_headers()
                if data is not None:
                    self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


def npm_tarball(script: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data, mode in (("package/claude", script.encode(), 0o755), ("package/package.json", b"{}", 0o644)):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@pytest.fixture
def served_pins(tmp_path, monkeypatch):
    """pins.json whose downloads come from a local server, and a stand-in venv builder."""
    tarball = npm_tarball(f'#!/bin/sh\necho "{pins.CLAUDE_CODE_VERSION} (Claude Code)"\n')
    files = {"/npm/claude.tgz": tarball}
    files.update({f"/raw/{rel}": (CCSR_DIR / rel).read_bytes() for rel in pins.CCSR_FILES})
    server = Server(files)
    data = pins.as_dict()
    for entry in data["claude_code_packages"].values():
        entry.update(url=server.base + "/npm/claude.tgz", sha256=hashlib.sha256(tarball).hexdigest(),
                     integrity="sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode())
    data["ccsr_raw_url"] = server.base + "/raw/{path}"
    data["install_dir"] = str(tmp_path / "baked" / "claude-review")
    pins_file = tmp_path / "work" / "pins.json"
    pins_file.parent.mkdir()
    pins_file.write_text(json.dumps(data))
    (tmp_path / "work" / pins.REQUIREMENTS_FILE).write_bytes((HERE / pins.REQUIREMENTS_FILE).read_bytes())
    built = []

    def fake_venv(part, requirements, python, uv, home, deadline):
        """No PyPI here: a stand-in venv Python that reports the pinned versions."""
        built.append((part, requirements))
        probe = json.dumps({"python": "3.12.11", "anthropic": pins.ANTHROPIC_VERSION,
                            "requests": pins.REQUESTS_VERSION})
        _exe(Path(part) / "venv" / "bin" / "python", f"#!/bin/sh\necho '{probe}'\n")

    monkeypatch.setattr(install, "install_venv", fake_venv)
    monkeypatch.setattr(install, "ROOT", str(tmp_path / "work"))
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    yield pins_file, data, server, built
    server.server.shutdown()


@pytest.mark.skipif(platform.machine().lower() not in ("x86_64", "amd64", "aarch64", "arm64")
                    or platform.libc_ver()[0] != "glibc", reason="the installer supports glibc x86_64/aarch64 only")
def test_setup_installs_when_nothing_is_baked(tmp_path, served_pins, capsys):
    pins_file, data, _, built = served_pins
    assert install.main([str(pins_file), "--budget-sec", "120"]) == 0
    out = capsys.readouterr().out
    result = json.loads(out.strip().splitlines()[-1].split(" ", 1)[1])
    assert result["source"] == "setup" and "no executable" in result["baked_problem"]
    part = tmp_path / "work" / "claude-review"
    assert result["part"] == str(part) and built == [(str(part), str(tmp_path / "work" / pins.REQUIREMENTS_FILE))]
    assert (part / "bin" / "claude").stat().st_mode & 0o111
    assert json.loads((part / "install.json").read_text())["pins"] == data
    assert not (tmp_path / "work" / "claude-review.partial").exists()


@pytest.mark.skipif(platform.libc_ver()[0] != "glibc", reason="glibc only")
def test_a_baked_part_with_a_broken_probe_is_reinstalled(tmp_path, served_pins, capsys):
    pins_file, data, _, built = served_pins
    baked = fake_part(Path(data["install_dir"]))
    _exe(baked / "venv" / "bin" / "python", "#!/bin/sh\necho 'Segmentation fault'\n")
    assert install.main([str(pins_file), "--budget-sec", "120"]) == 0
    result = json.loads(capsys.readouterr().out.strip().splitlines()[-1].split(" ", 1)[1])
    assert result["source"] == "setup" and "printed no JSON result" in result["baked_problem"]
    assert built


@pytest.mark.skipif(platform.libc_ver()[0] != "glibc", reason="glibc only")
def test_setup_uses_a_baked_part_without_downloading(tmp_path, served_pins, capsys):
    pins_file, data, server, built = served_pins
    fake_part(Path(data["install_dir"]))
    server.server.shutdown()  # nothing may be fetched
    assert install.main([str(pins_file)]) == 0
    result = json.loads(capsys.readouterr().out.strip().splitlines()[-1].split(" ", 1)[1])
    assert result["source"] == "image" and result["part"] == data["install_dir"] and built == []


@pytest.mark.skipif(platform.libc_ver()[0] != "glibc", reason="glibc only")
@pytest.mark.parametrize("field, value, message", [
    ("sha256", "0" * 64, "has sha256"),
    ("integrity", "sha512-AAAA", "does not match its npm integrity"),
])
def test_setup_refuses_a_tarball_that_does_not_match(tmp_path, served_pins, capsys, field, value, message):
    pins_file, data, _, _ = served_pins
    for entry in data["claude_code_packages"].values():
        entry[field] = value
    pins_file.write_text(json.dumps(data))
    with pytest.raises(SystemExit) as raised:
        install.main([str(pins_file)])
    assert raised.value.code == 2
    assert message in capsys.readouterr().out
    assert not (tmp_path / "work" / "claude-review" / "bin" / "claude").exists()


@pytest.mark.skipif(platform.libc_ver()[0] != "glibc", reason="glibc only")
def test_setup_refuses_a_changed_upstream_file(tmp_path, served_pins, capsys):
    pins_file, data, _, _ = served_pins
    data["ccsr_files"]["claudecode/prompts.py"] = "f" * 64
    pins_file.write_text(json.dumps(data))
    with pytest.raises(SystemExit):
        install.main([str(pins_file)])
    assert "prompts.py has sha256" in capsys.readouterr().out


def test_build_requires_the_images_own_python(tmp_path, monkeypatch):
    monkeypatch.setattr(install, "choose_python", lambda explicit: ("/usr/bin/python3", (3, 11)))
    with pytest.raises(install.InstallError, match="must be built from the CPython under /opt/sast/python/"):
        install.install(str(tmp_path / "part"), pins.as_dict(), str(HERE / pins.REQUIREMENTS_FILE), None, None,
                        str(tmp_path), 10**12, python_prefix=install.BUILD_PYTHON_PREFIX)


def test_installer_is_stdlib_only():
    tree = __import__("ast").parse((HERE / "install.py").read_text())
    imported = {alias.name.split(".")[0] for node in __import__("ast").walk(tree)
                if isinstance(node, __import__("ast").Import) for alias in node.names}
    imported |= {node.module.split(".")[0] for node in __import__("ast").walk(tree)
                 if isinstance(node, __import__("ast").ImportFrom) and node.module}
    assert imported - set(__import__("sys").stdlib_module_names) == {"sast_manifest"}


# ---------------------------------------------------------------- the tools image


def test_dockerfile_builds_the_part_and_the_manifest_covers_it():
    text = (ROOT / "images" / "sast-tools" / "Dockerfile").read_text()
    stage = text.split(" AS claude-review\n", 1)[1].split("\nFROM ", 1)[0]
    assert "COPY --from=semgrep /opt/sast/python /opt/sast/python" in stage
    assert "COPY --from=semgrep /opt/sast/bin /opt/sast/bin" in stage
    assert "claude_review_install.py /tmp/claude-review/claude_review_pins.json" in stage and "--build" in stage
    assert "--requirements /tmp/claude-review/requirements.lock" in stage
    manifest_stage = text.split(" AS manifest\n", 1)[1].split("FROM scratch", 1)[0]
    assert "COPY --from=claude-review /opt/sast/claude-review /opt/sast/claude-review" in manifest_stage
    assert manifest.PARTS["claude-review"] == ("claude-review",)
    assert manifest.VERSION_KEYS["claude-review"] == "claude_code_version"


def test_build_script_stages_the_part(tmp_path):
    script = (ROOT / "tools" / "build_tools_image.sh").read_text()
    assert 'cp "$ROOT/sast/claude_review/install.py" "$CONTEXT/claude_review_install.py"' in script
    assert 'cp "$ROOT/sast/claude_review/requirements.lock" "$CONTEXT/requirements.lock"' in script
    assert '> "$CONTEXT/claude_review_pins.json"' in script


def test_manifest_covers_and_rehashes_the_part(tmp_path):
    from tests.test_image_manifest import ALL_PINS, fake_tree

    root = fake_tree(tmp_path / "sast")
    fake_part(root / "claude-review")
    pins_file = tmp_path / "manifest_pins.json"
    pins_file.write_text(json.dumps(ALL_PINS))
    assert manifest.write(str(root), str(pins_file)) == 0
    doc = json.loads((root / "MANIFEST.json").read_text())
    assert doc["tools"]["claude-review"]["version"] == pins.CLAUDE_CODE_VERSION
    assert doc["parts"]["claude-review"]["files"] == 2 + len(pins.CCSR_FILES)
    assert manifest.check("claude-review", root=str(root))["status"] == "verified"


# ---------------------------------------------------------------- scoped texts


def _upstream_default_filter_text() -> str:
    source = (CCSR_DIR / "claudecode" / "claude_api_client.py").read_text()
    start = source.index('filtering_section = """') + len('filtering_section = """')
    return source[start:source.index('"""', start)]


def test_scoped_filter_text_is_the_upstream_default_without_two_exclusions():
    default = _upstream_default_filter_text()
    hard, rest = default.split("\n\nSIGNAL QUALITY CRITERIA", 1)
    items = re.findall(r"^\d+\. (.*)$", hard, re.MULTILINE)
    assert items[6].startswith("A lack of hardening measures") and items[13].startswith("Including user-controlled")
    expected_items = [item for i, item in enumerate(items) if i not in (6, 13)]
    ours = (HERE / "scoped_filter_instructions.txt").read_text()
    our_hard, our_rest = ours.split("\n\nSIGNAL QUALITY CRITERIA", 1)
    assert re.findall(r"^\d+\. (.*)$", our_hard, re.MULTILINE) == expected_items
    assert [int(n) for n in re.findall(r"^(\d+)\. ", our_hard, re.MULTILINE)] == list(range(1, 15))
    assert our_rest.rstrip("\n") == rest


def test_scoped_scan_text_uses_the_upstream_format_and_leaks_no_label():
    spec = importlib.util.spec_from_file_location("leak_scan", ROOT / "tools" / "leak_scan.py")
    leak_scan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(leak_scan)
    SHINGLE, shingles, truth_strings, words = (leak_scan.SHINGLE, leak_scan.shingles, leak_scan.truth_strings,
                                               leak_scan.words)

    text = (HERE / "scoped_scan_instructions.txt").read_text()
    headers = re.findall(r"^\*\*(.+):\*\*$", text, re.MULTILINE)
    assert len(headers) == 3 and all(line.startswith(("**", "- ")) for line in text.splitlines() if line)
    assert "security_manifest.json" in text and '"cwe"' in text
    assert "—" not in text and ";" not in text
    ours = shingles(words(text), SHINGLE)
    for truth in SAMPLE_TASKS.glob("*/tests/ground_truth.json"):
        for _, value in truth_strings(json.loads(truth.read_text())):
            overlap = ours & shingles(words(value), SHINGLE)
            assert not overlap, (truth, value, overlap)
    for name in (p.name for p in SAMPLE_TASKS.iterdir()):
        assert name not in text


def test_vendored_upstream_copy_is_complete_and_licensed():
    assert (FIXTURES / "ccsr_0c6a49f" / "LICENSE").read_text().startswith("MIT License")
    vendored = [p for p in CCSR_DIR.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    assert sorted(str(p.relative_to(CCSR_DIR)) for p in vendored) == sorted(pins.CCSR_FILES)

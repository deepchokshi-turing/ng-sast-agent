"""install.py's pure parts: which rule files are kept, and the content digest.

The full install is exercised by the Docker/Harbor runs (README), since it needs
the network.
"""

import importlib.util
import io
import tarfile

import pytest

from sast.semgrep import pins
from tests.conftest import ROOT


@pytest.fixture(scope="module")
def install():
    spec = importlib.util.spec_from_file_location("install", ROOT / "sast" / "semgrep" / "install.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive(tmp_path, files):
    path = tmp_path / "rules.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def test_keeps_rule_yaml_in_the_pinned_folders_only(install, tmp_path):
    top = "semgrep-rules-abc/"
    path = archive(tmp_path, {
        top + "python/lang/a.yaml": b"rules: []\n",
        top + "python/lang/a.py": b"eval(x)\n",              # test target, not a rule
        top + "python/lang/a.test.yaml": b"rules: []\n",     # test fixture
        top + "generic/secrets/b.yml": b"rules: []\n",
        top + "generic/other/c.yaml": b"rules: []\n",        # folder not pinned
        top + "java/d.yaml": b"rules: []\n",
    })
    files = install.read_rules_archive(str(path), ["python", "generic/secrets"])
    assert [rel for rel, _ in files] == ["generic/secrets/b.yml", "python/lang/a.yaml"]


def test_unsafe_paths_are_refused(install):
    with pytest.raises(SystemExit):
        install.select_rule_files(["top/python/../../etc/x.yaml"], "top/", ["python"])


def test_digest_depends_on_content_not_order(install):
    a = [("python/a.yaml", b"1"), ("python/b.yaml", b"2")]
    assert install.rules_digest(a) == install.rules_digest(list(reversed(a)))
    assert install.rules_digest(a) != install.rules_digest([("python/a.yaml", b"1"), ("python/b.yaml", b"3")])
    assert install.rules_digest(a) != install.rules_digest([("python/a.yaml", b"1"), ("python/c.yaml", b"2")])


def test_pins_are_complete(install):
    p = pins.as_dict()
    assert set(p["uv_sha256"]) == set(install.ARCH.values())
    assert len(p["rules_commit"]) == 40 and len(p["rules_digest"]) == 64


def test_no_reuse_without_a_previous_install(install, monkeypatch, tmp_path):
    monkeypatch.setattr(install, "RESULT_FILE", str(tmp_path / "install.json"))
    assert install.installed(pins.as_dict()) is None
    (tmp_path / "install.json").write_text('{"pins": {"semgrep_version": "0"}}')
    assert install.installed(pins.as_dict()) is None

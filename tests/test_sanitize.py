from packetgen.sanitize import load_denylist, main, sanitize_findings

# Built at runtime so this file never contains a literal public IP, real MAC or home path (the gate scans it too).
PUBLIC_IP = ".".join(["8"] * 4)
REAL_MAC = ":".join(["3c", "22", "fb", "12", "34", "56"])
HOME_PATHS = ("/" + "Users/alice/notes/x.md", "/" + "home/bob/work", "C:" + "\\Users\\carol\\docs")


def checks(text: str) -> list[str]:
    return [f["check"] for f in sanitize_findings(text, "t")]


def test_allows_doc_and_private_ips():
    text = "192.0.2.1 10.1.1.1 172.24.23.6 255.255.255.0 224.0.0.5 198.51.100.7 203.0.113.9"
    assert checks(text) == []


def test_flags_public_ip():
    assert checks(f"dst outside:{PUBLIC_IP}/53") == ["Z1"]


def test_allows_doc_macs_all_notations():
    assert checks("00:00:5e:00:53:0a 0000.5e00.530a 00-00-5E-00-53-0A") == []


def test_flags_real_mac():
    assert checks(f"client {REAL_MAC} joined") == ["Z2"]


def test_ignores_version_strings():
    assert checks("IOS XE 17.9.4 and PAN-OS 11.1.2") == []


def test_blocks_binary_artifacts(tmp_path):
    from packetgen.sanitize import file_findings
    for name in ("logs.xlsx", "telemetry.pdf", "capture.pcap", "capture.pcapng"):
        path = tmp_path / name
        path.write_bytes(b"x")
        assert [f["check"] for f in file_findings(path)] == ["Z3"], name


def test_file_findings_scans_text(tmp_path):
    from packetgen.sanitize import file_findings
    path = tmp_path / "notes.txt"
    path.write_text(f"peer {PUBLIC_IP}")
    assert [f["check"] for f in file_findings(path)] == ["Z1"]


def test_allows_all_zero_placeholder_mac():
    assert checks("source MAC 0000.0000.0000 (placeholder)") == []


def test_flags_home_paths():
    for text in HOME_PATHS:
        assert [f["check"] for f in sanitize_findings(text, "t")] == ["Z4"], text


def test_flags_bare_and_wrapped_home_paths():
    u, h = "/" + "Users/alice", "/" + "home/bob"
    for text in (u, f"`{u}`", f"see {h}.", f'"{u}"', "C:" + "\\\\Users\\\\carol\\\\x", "C:" + "\\Users\\carol"):
        assert [f["check"] for f in sanitize_findings(text, "t")] == ["Z4"], text


def test_home_path_ignores_urls():
    assert sanitize_findings("https://example.com/" + "home/bob/page and a/" + "Users/x/y", "t") == []


def test_deny_term_matches_across_line_wrap():
    f = sanitize_findings("worked at Acme\n  Corp today", "t", deny=["Acme Corp"])
    assert [x["check"] for x in f] == ["Z5"]


def test_allows_tilde_config_paths():
    assert sanitize_findings("read ~/.config/claude-skills/profile.md and ~/.claude/skills", "t") == []


def test_deny_terms_literal_and_case_insensitive():
    f = sanitize_findings("worked at ACME corp on c++ and aXb", "t", deny=["Acme Corp", "C++", "a.b"])
    assert [x["check"] for x in f] == ["Z5", "Z5"]   # "a.b" must not match "aXb"


def test_load_denylist_skips_blank_and_comments(tmp_path):
    p = tmp_path / ".sanitize-deny"
    p.write_text("# personal terms\n\nAcme Corp\n  Widget Lab  \n")
    assert load_denylist(p) == ["Acme Corp", "Widget Lab"]


def test_load_denylist_missing_file(tmp_path):
    assert load_denylist(tmp_path / "nope") == []


def test_main_uses_local_denylist(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".sanitize-deny").write_text("Acme Corp\n")
    (tmp_path / "a.md").write_text("ex-Acme Corp engineer")
    assert main(["a.md"]) == 1
    (tmp_path / ".sanitize-deny").write_text("# none\n")
    assert main(["a.md"]) == 0


# ---- leak gate fixes (review 2026-11-09, findings 1-3) ----
import os
import shutil
import subprocess
from pathlib import Path

from packetgen.sanitize import deny_path

REPO = Path(__file__).resolve().parents[1]
# Built at runtime, like PUBLIC_IP: a global-unicast IPv6 address outside every allowed range.
PUBLIC_V6 = ":".join(["2606", "4700", "4700"]) + "::" + "1111"


def test_flags_public_ipv6():
    assert checks(f"dns server {PUBLIC_V6} unreachable") == ["Z1"]


def test_allows_doc_link_local_ula_and_multicast_ipv6():
    text = ("2001:db8:acad:1::1/64 3fff:0:1::5 fe80::a00:27ff:fe5d:6d6%11 fe80::1 "
            "fd00:10::1 ff02::1 ff02::1:2 ::1 ::")
    assert checks(text) == []


def test_ipv6_regex_ignores_macs_times_and_versions():
    text = "00:00:5e:00:53:0a at 12:00:01.123 on 17.9.4, uptime 1:02:03"
    assert checks(text) == []


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def _repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")
    return root


def test_deny_path_resolves_to_main_checkout_from_a_worktree(tmp_path):
    root = _repo(tmp_path)
    (root / "a.txt").write_text("x")
    _git(root, "add", "a.txt")
    _git(root, "commit", "-q", "-m", "init")
    wt = tmp_path / "wt"
    _git(root, "worktree", "add", "-q", str(wt))
    assert deny_path(wt).resolve() == (root / ".sanitize-deny").resolve()
    assert deny_path(root).resolve() == (root / ".sanitize-deny").resolve()


def test_missing_denylist_fails_when_required(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    (root / "a.md").write_text("plain text")
    monkeypatch.chdir(root)
    assert main(["a.md"]) == 0                       # strangers' clones: no list, no failure
    _git(root, "config", "packetgen.requireDeny", "true")
    assert main(["a.md"]) == 1                       # a clone that sets requireDeny: missing list = loud stop


def test_hook_scans_staged_content_not_working_tree(tmp_path):
    root = _repo(tmp_path)
    (root / "scripts").mkdir()
    shutil.copy(REPO / "scripts" / "pre-commit", root / "scripts" / "pre-commit")
    (root / "src").symlink_to(REPO / "src")
    if (REPO / ".venv").exists():
        (root / ".venv").symlink_to(REPO / ".venv")
    (root / ".gitignore").write_text("src\n.venv\n")
    _git(root, "config", "core.hooksPath", "scripts")
    env = {**os.environ, "GIT_AUTHOR_DATE": "2026-01-01T00:00:00", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00"}
    f = root / "notes.md"
    f.write_text(f"peer {PUBLIC_IP}\n")
    _git(root, "add", "notes.md", ".gitignore")
    f.write_text("peer 192.0.2.1\n")                 # clean working copy, dirty staged blob
    bad = subprocess.run(["git", "commit", "-q", "-m", "bad"], cwd=root, capture_output=True, text=True, env=env)
    assert bad.returncode != 0, bad.stdout + bad.stderr
    _git(root, "add", "notes.md")
    good = subprocess.run(["git", "commit", "-q", "-m", "good"], cwd=root, capture_output=True, text=True, env=env)
    assert good.returncode == 0, good.stdout + good.stderr


# ---- security review of 49f14ec ----
def test_ipv6_at_sentence_end_or_after_a_period_is_still_caught():
    assert checks(f"dns server {PUBLIC_V6}.") == ["Z1"]
    assert checks(f"see.{PUBLIC_V6} now") == ["Z1"]


def test_deny_path_prefers_this_checkouts_own_list(tmp_path):
    root = _repo(tmp_path)
    (root / "a.txt").write_text("x")
    _git(root, "add", "a.txt")
    _git(root, "commit", "-q", "-m", "init")
    wt = tmp_path / "wt"
    _git(root, "worktree", "add", "-q", str(wt))
    (wt / ".sanitize-deny").write_text("Acme\n")
    assert deny_path(wt).resolve() == (wt / ".sanitize-deny").resolve()


def test_symlink_is_scanned_as_its_target_text_not_followed(tmp_path):
    from packetgen.sanitize import file_findings
    secret = tmp_path / "secret.txt"
    secret.write_text(f"peer {PUBLIC_IP}")
    link = tmp_path / "link"
    link.symlink_to("/" + "Users/alice/notes")
    assert [f["check"] for f in file_findings(link)] == ["Z4"]
    link2 = tmp_path / "link2"
    link2.symlink_to(secret)
    assert all(f["check"] != "Z1" for f in file_findings(link2))   # the target file is never read


def test_hook_scans_staged_symlinks(tmp_path):
    root = _repo(tmp_path)
    (root / "scripts").mkdir()
    shutil.copy(REPO / "scripts" / "pre-commit", root / "scripts" / "pre-commit")
    (root / "src").symlink_to(REPO / "src")
    if (REPO / ".venv").exists():
        (root / ".venv").symlink_to(REPO / ".venv")
    (root / ".gitignore").write_text("src\n.venv\n")
    _git(root, "config", "core.hooksPath", "scripts")
    (root / "notes").symlink_to("/" + "Users/alice/private")
    _git(root, "add", "notes", ".gitignore")
    bad = subprocess.run(["git", "commit", "-q", "-m", "bad"], cwd=root, capture_output=True, text=True)
    assert bad.returncode != 0, bad.stdout + bad.stderr

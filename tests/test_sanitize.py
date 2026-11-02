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

import copy
import json
from pathlib import Path

from packetgen import cli
from packetgen.patterns import check_patterns, load_patterns, select_patterns
from packetgen.registry import load_registry
from packetgen.timebase import STYLES

ROOT = Path(__file__).resolve().parents[1]
REG = load_registry(ROOT / "registry")
STARTER = ROOT / "scenarios" / "starter.yaml"


def pats() -> list[dict]:
    return copy.deepcopy(load_patterns(STARTER))


def checks(p: list[dict]) -> set[str]:
    return {f["check"] for f in check_patterns(p, REG)}


def test_starter_catalog_clean():
    assert check_patterns(load_patterns(STARTER), REG) == []


def test_unknown_id_P1():
    p = pats()
    p[0]["registry_ids"].append("IOS:NOPE-1-NOPE")
    assert "P1" in checks(p)


def test_unverified_id_P2():
    p = pats()
    rid = next(i for i, e in REG.items() if not e["verified"])
    p[0]["registry_ids"].append(rid)
    assert "P2" in checks(p)


def test_unsupported_header_P3():
    p = pats()
    reg = {**REG, "TEST:SYNTH-1-NOSTYLE": {"verified": True, "header_style": None}}
    p[0]["registry_ids"].append("TEST:SYNTH-1-NOSTYLE")
    assert "P3" in {f["check"] for f in check_patterns(p, reg)}


def test_bad_cert_P4():
    p = pats()
    p[0]["cert"] = "CCNA"
    assert "P4" in checks(p)


def test_missing_topic_P4():
    p = pats()
    del p[0]["topic"]
    assert "P4" in checks(p)


def test_duplicate_id_P5():
    p = pats()
    p.append(copy.deepcopy(p[0]))
    assert "P5" in checks(p)


def test_missing_key_P6():
    p = pats()
    del p[0]["symptom"]
    assert "P6" in checks(p)


def test_findings_are_json():
    p = pats()
    p[0]["cert"] = "CCNA"
    p[0]["registry_ids"].append("IOS:NOPE-1-NOPE")
    json.dumps(check_patterns(p, REG))


def test_select_by_cert_encor_excludes_radius():
    assert "radius-server-dead-dot1x" not in select_patterns(pats(), cert="ENCOR")


def test_select_by_topic():
    assert select_patterns(pats(), topic="ntp") == ["ntp-unsynced-log-skew"]


def test_select_exclude_all_returns_empty():
    p = pats()
    ids = select_patterns(p, cert="ENCOR")
    assert ids and select_patterns(p, cert="ENCOR", exclude=ids) == []


def test_cli_patterns_exit_codes(capsys):
    assert cli.main(["patterns", "--cert", "ENCOR"]) == 0
    out = capsys.readouterr().out.split()
    assert "ntp-unsynced-log-skew" in out and "radius-server-dead-dot1x" not in out
    assert cli.main(["patterns", "--topic", "ntp", "--exclude", "ntp-unsynced-log-skew"]) == 1


def test_cli_patterns_bad_filter_values(capsys):
    assert cli.main(["patterns", "--topic", "hsrp"]) == 2
    assert "fhrp" in capsys.readouterr().err
    assert cli.main(["patterns", "--cert", "encor"]) == 2
    assert "ENCOR" in capsys.readouterr().err


def test_cli_patterns_invalid_catalog_exit_2(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("- id: x\n  topic: ospf\n  cert: ENCOR\n  symptom: s\n  root_cause: r\n"
                   "  registry_ids: [IOS:NOPE-1-NOPE]\n  red_herrings: [a]\n")
    assert cli.main(["patterns", "--file", str(bad)]) == 2

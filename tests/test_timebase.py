import pytest

from packetgen.timebase import header, parse_utc

T0 = "2025-06-01T12:00:00Z"
DEV = {"hostname": "ACC-SW1", "tz_offset_min": 0, "clock": "ntp"}


def test_ios_header():
    assert header("ios", parse_utc(T0), DEV) == "Jun  1 12:00:00.000 UTC: "


def test_ios_header_with_seq_and_ms():
    t = parse_utc("2025-06-01T12:00:00.483Z")
    assert header("ios", t, DEV, seq=42) == "42: Jun  1 12:00:00.483 UTC: "


def test_nxos_header():
    assert header("nxos", parse_utc(T0), DEV) == "2025 Jun  1 12:00:00 ACC-SW1 "


def test_asa_header():
    assert header("asa", parse_utc(T0), DEV) == "Jun 01 2025 12:00:00 ACC-SW1 : "


def test_bsd_header():
    assert header("bsd", parse_utc(T0), DEV) == "Jun  1 12:00:00 ACC-SW1 "


def test_meraki_header_is_utc_epoch():
    dev = {**DEV, "tz_offset_min": -360}
    assert header("meraki", parse_utc(T0), dev) == "1748779200.000000000 ACC-SW1 "


def test_tz_offset_applied():
    dev = {**DEV, "tz_offset_min": -360}
    assert header("ios", parse_utc(T0), dev) == "Jun  1 06:00:00.000 -06:00: "


def test_skew_applied():
    dev = {**DEV, "clock": "unsynced", "skew_s": 95}
    assert header("bsd", parse_utc(T0), dev) == "Jun  1 12:01:35 ACC-SW1 "


def test_naive_rejected():
    with pytest.raises(ValueError):
        parse_utc("2025-06-01 12:00")


def test_offset_normalized():
    assert parse_utc("2025-06-01T14:00:00+02:00") == parse_utc(T0)


def test_unknown_style_rejected():
    with pytest.raises(ValueError):
        header("panos", parse_utc(T0), DEV)

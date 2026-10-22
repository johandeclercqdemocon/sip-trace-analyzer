"""Every scenario plants known faults; the analyser must find exactly those."""
from __future__ import annotations

import pathlib
import re
import sys
from datetime import datetime

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from analyzer import model, readers  # noqa: E402
from analyzer.checks import Context, run_all  # noqa: E402
from tests import builder, scenarios  # noqa: E402


def requires_knowledge_base():
    """Skip clearly rather than fail cryptically when the stack is not running.

    Two tests read the catalog out of Postgres. A new checkout running `make test`
    before `make up` should be told that, not shown a connection traceback.
    """
    from analyzer.report import Knowledge
    try:
        return Knowledge.load()
    except Exception as exc:                                    # noqa: BLE001
        pytest.skip(f"knowledge base unreachable ({type(exc).__name__}); "
                    f"start it with 'make up'")


def analyse(path: pathlib.Path):
    trace = readers.read(path)
    calls, streams = model.build(trace)
    ctx = Context(trace=trace, calls=calls, streams=streams)
    return trace, calls, streams, run_all(ctx)


@pytest.mark.parametrize("scenario", scenarios.ALL, ids=lambda f: f.__name__)
def test_scenario_finds_exactly_the_seeded_faults(scenario):
    path, expected = scenario()
    _, _, _, findings = analyse(path)
    found = {f.check_id for f in findings}
    missing = expected - found
    spurious = found - expected
    assert not missing, f"missed {sorted(missing)} (found {sorted(found)})"
    assert not spurious, f"false positives {sorted(spurious)}"


def test_clean_call_is_silent():
    path, _ = scenarios.clean_call()
    _, calls, streams, findings = analyse(path)
    assert len(calls) == 1
    assert calls[0].outcome == "answered"
    assert len(streams) == 2
    assert findings == []


def test_dialog_and_offer_answer_reconstruction():
    path, _ = scenarios.clean_call()
    _, calls, _, _ = analyse(path)
    call = calls[0]
    assert len(call.dialogs) == 1
    d = call.dialogs[0]
    assert d.confirmed
    assert d.invite is not None
    ex = d.negotiated
    assert ex is not None and ex.complete
    assert ex.offer_sdp.audio().port == scenarios.CALLER_MEDIA
    assert ex.answer_sdp.audio().port == scenarios.CALLEE_MEDIA


def test_response_matches_its_transaction_through_nat():
    """RFC 3261 17.1.3 matches on branch and CSeq method only, never the Via sent-by."""
    path, _ = scenarios.nat_private()
    _, calls, _, _ = analyse(path)
    call = calls[0]
    assert call.outcome == "answered"
    inv = call.initial_invite
    assert inv is not None and inv.final is not None and inv.final.status == 200


def test_transaction_grouping_handles_retransmissions():
    path, _ = scenarios.invite_timeout()
    _, calls, _, _ = analyse(path)
    txns = calls[0].invite_transactions
    assert len(txns) == 1, "retransmissions must not create new transactions"
    assert len(txns[0].requests) == 7


def test_text_log_reader_recovers_endpoints_and_timing():
    path, _ = scenarios.text_log()
    trace, calls, streams, _ = analyse(path)
    assert len(trace.messages) == 6
    assert not trace.has_media_layer
    assert streams == []
    first = trace.messages[0]
    assert first.src.startswith(scenarios.CALLER)
    assert first.timestamp > 0
    assert trace.messages[-1].timestamp > first.timestamp


def _dateless_log(tmp_path: pathlib.Path, entries: list[tuple[str, str]]) -> pathlib.Path:
    """A text log whose preamble lines carry a time of day but no date.

    One preamble + one SIP message per entry, in file order. Documentation
    addresses and builder message templates, as everywhere else here.
    """
    out = []
    for tod, raw in entries:
        out.append(f"{tod} 203.0.113.10:5060 -> 198.51.100.20:5060")
        out.append(raw)
        out.append("")
    path = tmp_path / "dateless.log"
    path.write_text("\n".join(out))
    return path


def test_a_dateless_log_crossing_midnight_keeps_the_call_order(tmp_path):
    """The INVITE precedes its own 100/200/ACK, and the call lasts 0.5 s, not a day."""
    cid = "midnight-1@example.net"
    entries = [
        ("23:59:59.900000", builder.invite(cid, body="")),
        ("00:00:00.050000", builder.response(100, "Trying", cid, ttag="")),
        ("00:00:00.300000", builder.response(200, "OK", cid)),
        ("00:00:00.400000", builder.request("ACK", cid, cseq=1,
                                            branch="z9hG4bK-ack-1")),
    ]
    trace = readers.read(_dateless_log(tmp_path, entries))
    assert [m.status or m.method for m in trace.messages] == ["INVITE", 100, 200, "ACK"]
    stamps = [m.timestamp for m in trace.messages]
    assert abs(stamps[0] - 86399.9) < 1e-6
    assert abs(stamps[1] - 86400.05) < 1e-6
    assert abs(stamps[-1] - stamps[0] - 0.5) < 1e-6


def test_a_dateless_log_through_two_midnights_counts_the_days(tmp_path):
    """Each backwards jump past half a day adds one more day to what follows."""
    tods = ["23:59:59.000000", "00:00:01.000000", "12:00:00.000000",
            "23:59:58.000000", "00:00:02.000000"]
    entries = [(tod, builder.request("OPTIONS", f"keepalive-{n}@example.net",
                                     branch=f"z9hG4bK-o{n}", cseq=n))
               for n, tod in enumerate(tods, start=1)]
    trace = readers.read(_dateless_log(tmp_path, entries))
    assert [round(m.timestamp, 3) for m in trace.messages] == [
        86399.0, 86401.0, 129600.0, 172798.0, 172802.0]


def test_a_small_step_back_in_a_dateless_log_is_not_a_new_day(tmp_path):
    """One second back is a log written slightly out of order, not midnight."""
    entries = [
        ("10:00:05.000000", builder.request("OPTIONS", "ka-1@example.net",
                                            branch="z9hG4bK-o1", cseq=1)),
        ("10:00:04.000000", builder.request("OPTIONS", "ka-2@example.net",
                                            branch="z9hG4bK-o2", cseq=1)),
    ]
    trace = readers.read(_dateless_log(tmp_path, entries))
    assert [round(m.timestamp, 3) for m in trace.messages] == [36004.0, 36005.0]


def test_a_step_back_of_exactly_twelve_hours_is_not_a_new_day(tmp_path):
    entries = [
        ("12:00:00.000000", builder.request("OPTIONS", "ka-1@example.net",
                                            branch="z9hG4bK-o1", cseq=1)),
        ("00:00:00.000000", builder.request("OPTIONS", "ka-2@example.net",
                                            branch="z9hG4bK-o2", cseq=1)),
    ]
    trace = readers.read(_dateless_log(tmp_path, entries))
    assert [round(m.timestamp, 3) for m in trace.messages] == [0.0, 43200.0]


def test_dated_timestamps_in_a_log_are_never_shifted(tmp_path):
    """A timestamp that carries its own date already knows which day it is on,
    even when the file order goes back a day."""
    entries = [
        ("2024-01-02 10:00:00.000000", builder.request("OPTIONS", "ka-1@example.net",
                                                       branch="z9hG4bK-o1", cseq=1)),
        ("2024-01-01 10:00:00.000000", builder.request("OPTIONS", "ka-2@example.net",
                                                       branch="z9hG4bK-o2", cseq=1)),
    ]
    path = tmp_path / "dated.log"
    path.write_text("\n".join(f"{tod} 203.0.113.10:5060 -> 198.51.100.20:5060\n{raw}\n"
                              for tod, raw in entries))
    trace = readers.read(path)
    want = sorted([datetime(2024, 1, 2, 10).timestamp(),
                   datetime(2024, 1, 1, 10).timestamp()])
    assert [round(m.timestamp, 3) for m in trace.messages] == [round(w, 3) for w in want]


def test_rtp_checks_stay_silent_without_a_media_layer():
    path, _ = scenarios.text_log()
    _, _, _, findings = analyse(path)
    assert not [f for f in findings if f.check_id.startswith("RTP")]


def test_loss_measurement_is_accurate():
    path, _ = scenarios.packet_loss()
    _, _, streams, _ = analyse(path)
    lossy = [s for s in streams if s.lost]
    assert len(lossy) == 1
    assert lossy[0].lost == 20            # 250 packets, one dropped every 12th from index 10
    assert 0.07 < lossy[0].loss_ratio < 0.09


def test_retransmitted_2xx_is_one_problem_not_five():
    path, _ = scenarios.missing_ack()
    _, _, _, findings = analyse(path)
    assert len([f for f in findings if f.check_id == "SIP-ACK-MISSING"]) == 1


def test_retransmissions_do_not_create_phantom_offers():
    """Five copies of one 200 OK must not read as four extra offer/answer exchanges."""
    path, _ = scenarios.missing_ack()
    _, calls, _, _ = analyse(path)
    d = calls[0].dialogs[0]
    assert len(d.exchanges) == 1
    ex = d.negotiated
    assert ex.offer_sdp.audio().port == scenarios.CALLER_MEDIA
    assert ex.answer_sdp.audio().port == scenarios.CALLEE_MEDIA


def test_stream_findings_are_attributed_to_their_call():
    path, _ = scenarios.packet_loss()
    _, calls, _, findings = analyse(path)
    gap = next(f for f in findings if f.check_id == "RTP-SEQUENCE-GAP")
    assert gap.call_id == calls[0].call_id


def test_mirrored_capture_is_not_mistaken_for_retransmission():
    """The whole point of layer-3 duplicate detection: a doubled capture of a
    healthy call must not report an ACK problem or a retransmit storm."""
    path, _ = scenarios.mirrored_capture()
    trace, calls, _, findings = analyse(path)

    assert len([m for m in trace.messages if m.is_duplicate]) == 7
    assert calls[0].outcome == "answered"

    ids = {f.check_id for f in findings}
    assert "SIP-2XX-RETRANSMIT" not in ids
    assert "SIP-ACK-MISSING" not in ids
    assert ids == {"CAP-DUPLICATE-FRAMES"}

    # Each INVITE transaction still sees exactly one request, not two.
    assert len(calls[0].initial_invite.requests) == 1


def test_duplicate_detection_keeps_real_retransmissions():
    """Retransmissions are >= T1 apart with different IP ids — never flagged."""
    path, _ = scenarios.missing_ack()
    trace, _, _, findings = analyse(path)
    assert not [m for m in trace.messages if m.is_duplicate]
    assert "SIP-2XX-RETRANSMIT" in {f.check_id for f in findings}


# ---------------------------------------------------------------- untimed text logs
# A log line need not carry a time; those messages get timestamp 0.0 with
# time_known False. Placeholder times are not timing evidence, so they must
# never mark two transmissions as one captured frame.
def _untimed_log(tmp_path: pathlib.Path, blocks: list[str]) -> pathlib.Path:
    """One endpoint preamble + one SIP message per block, no timestamps anywhere."""
    out = []
    for raw in blocks:
        out.append("203.0.113.10:5060 -> 198.51.100.20:5060")
        out.append(raw)
        out.append("")
    path = tmp_path / "untimed.log"
    path.write_text("\n".join(out))
    return path


def test_untimed_retransmission_is_not_a_capture_duplicate(tmp_path):
    """Two transmissions of one request in a log without times stay two messages.

    Both carry placeholder 0.0, which used to read as 'within the duplicate
    window' and silently swallowed the retransmission.
    """
    raw = builder.invite("untimed-ret@example.net", body="")
    trace = readers.read(_untimed_log(tmp_path, [raw, raw]))
    assert not any("no timestamps found" not in n for n in trace.notes), trace.notes
    assert [m.method for m in trace.messages] == ["INVITE", "INVITE"]
    assert not [m for m in trace.messages if m.is_duplicate], trace.notes
    calls, _ = model.build(trace)
    assert sum(len(t.retransmissions) for c in calls for t in c.transactions) == 1


def test_untimed_logs_with_an_ip_id_still_find_captured_duplicates(tmp_path):
    """A matching non-zero IPv4 id is packet identity, not timing: it still marks
    one datagram logged twice, even when the log gave no time for either."""
    pre = ("IP (tos 0x0, ttl 63, id 885, offset 0, flags [DF], proto UDP (17), "
           "length 367)\n"
           "203.0.113.10.5060 > 198.51.100.20.5060: [udp sum ok] SIP, length 339\n")
    raw = builder.invite("untimed-dup@example.net", body="")
    trace = readers.read(_untimed_log(tmp_path, [pre + raw, pre + raw]))
    assert len(trace.messages) == 2
    dupes = [m for m in trace.messages if m.is_duplicate]
    assert len(dupes) == 1
    assert dupes[0].duplicate_kind == "frame"
    assert all(not m.time_known for m in trace.messages)


def test_timed_text_log_duplicates_are_still_found(tmp_path):
    """The same message logged twice with real (equal) times is still a doubled
    capture: only unknown times lost their power to mark duplicates."""
    hdr = "U 2024/01/01 10:00:00.100000 203.0.113.10:5060 -> 198.51.100.20:5060\n"
    raw = builder.invite("timed-dup@example.net", body="")
    path = tmp_path / "timed.log"
    path.write_text(hdr + raw + "\n\n" + hdr + raw + "\n\n")
    trace = readers.read(path)
    assert len(trace.messages) == 2
    dupes = [m for m in trace.messages if m.is_duplicate]
    assert len(dupes) == 1
    assert dupes[0].duplicate_kind == "frame"
    assert all(m.time_known for m in trace.messages)


def test_tcpdump_verbose_format_is_parsed():
    """SIP indented under an IP line, with tcpdump's a.b.c.d.port endpoint form."""
    path, _ = scenarios.two_capture_points()
    trace, _, _, _ = analyse(path)
    assert len(trace.messages) == 4
    first = trace.messages[0]
    assert first.method == "REGISTER"
    assert first.src == "10.0.0.21:50210"
    assert first.dst == "10.1.0.150:5060"
    assert first.ip_id == 885 and first.ttl == 64
    assert first.time_known


def test_two_capture_points_are_not_retransmissions():
    """The same packet either side of a NAT must collapse to one message."""
    path, _ = scenarios.two_capture_points()
    trace, calls, _, findings = analyse(path)

    # nat_map pairs are sorted, so the inside address comes first here.
    assert trace.nat_map == [("10.1.0.150", "10.2.0.150")]
    assert sum(1 for m in trace.messages if m.duplicate_kind == "capture-point") == 2

    call = calls[0]
    assert len(call.messages) == 2 and len(call.duplicates) == 2
    for txn in call.transactions:
        assert len(txn.requests) <= 1, "one packet seen twice is not a retransmission"

    ids = {f.check_id for f in findings}
    assert ids == {"CAP-MULTIPLE-CAPTURE-POINTS"}
    assert "SIP-AUTH-LOOP" not in ids


def _nat_pcap(path: pathlib.Path, frames: list[tuple[float, str, int]]) -> pathlib.Path:
    """One REGISTER datagram per entry, each seen at its own capture point.

    Every entry is (time, source address, IPv4 id); the destination is the
    registrar throughout. Documentation addresses and fixed MACs, as
    tests/builder.py uses.
    """
    from scapy.all import IP, UDP, Ether, Raw, wrpcap

    raw = builder.request("REGISTER", "nat-retry@example.net", cseq=1, ttag="",
                          caller="10.0.0.10", callee=builder.CALLEE,
                          branch="z9hG4bK-nat-retry").replace("\n", "\r\n").encode()
    packets = []
    for t, src, ident in frames:
        pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
               / IP(src=src, dst=builder.CALLEE, id=ident)
               / UDP(sport=5060, dport=5060) / Raw(raw))
        pkt.time = t
        packets.append(pkt)
    wrpcap(str(path), packets)
    return path


def test_second_view_of_a_retransmission_is_excluded_too(tmp_path):
    """A REGISTER captured either side of a NAT, retransmitted 500 ms later and
    captured twice again: each transmission keeps one view, so two survive and
    two capture-point views are excluded — and the retransmission survives."""
    inside, outside = "10.0.0.10", "203.0.113.10"
    path = _nat_pcap(tmp_path / "nat-retry.pcap",
                     [(1.0, inside, 100), (1.001, outside, 100),
                      (1.5, inside, 101), (1.501, outside, 101)])
    trace = readers.read_pcap(path)

    views = [m for m in trace.messages if m.duplicate_kind == "capture-point"]
    kept = [m for m in trace.messages if not m.is_duplicate]
    assert len(kept) == 2 and len(views) == 2
    # Each excluded view belongs to its own transmission, not all to the first.
    assert [m.duplicate_of for m in views] == [kept[0].frame, kept[1].frame]
    assert trace.nat_map == [(inside, outside)]

    calls, _ = model.build(trace)
    assert len(calls) == 1
    assert [len(t.requests) for t in calls[0].transactions] == [2]


def test_a_retransmission_seen_once_is_never_a_capture_point_view(tmp_path):
    """The retransmission is a new datagram: seen at one point only, nothing may
    exclude it, however the NAT translates the address in between."""
    inside, outside = "10.0.0.10", "203.0.113.10"
    path = _nat_pcap(tmp_path / "nat-once.pcap",
                     [(1.0, inside, 100), (1.001, outside, 100), (1.5, inside, 101)])
    trace = readers.read_pcap(path)

    assert [m.duplicate_kind for m in trace.messages].count("capture-point") == 1
    assert len([m for m in trace.messages if not m.is_duplicate]) == 2

    calls, _ = model.build(trace)
    assert [len(t.requests) for t in calls[0].transactions] == [2]


def test_time_origin_includes_a_zero_first_frame():
    """A capture starting at epoch 0 must not shift the whole ladder; filtering
    falsy timestamps used to drop the first frame out of the minimum."""
    from analyzer.report import Report
    knowledge = requires_knowledge_base()
    path, _ = scenarios.mirrored_capture()
    trace, calls, streams, findings = analyse(path)
    assert min(m.timestamp for m in trace.messages) == 0.0
    report = Report(source="t", calls=calls, streams=streams, findings=findings,
                    knowledge=knowledge)
    assert report.t0 == 0.0


def test_header_expansion_reads_the_wire_format():
    path, _ = scenarios.clean_call()
    trace, _, _, _ = analyse(path)
    invite = next(m for m in trace.messages if m.method == "INVITE")
    names = [n for n, _ in invite.header_lines()]
    assert names[0] == "Via"
    assert "Call-ID" in names and "CSeq" in names
    assert invite.body_text.startswith("v=0")


def test_ocom_export_is_read_as_a_correlated_trace():
    """Devices, legs, timing and transport come out of the HTML export."""
    path, _ = scenarios.ocom_export()
    trace, calls, streams, _ = analyse(path)

    assert trace.kind == "ocom-html"
    assert not trace.has_media_layer and streams == []
    assert trace.device_order == ["uac-gw", "sbc-edge", "carrier-trunk"]

    first = trace.messages[0]
    assert first.method == "INVITE"
    assert first.src == f"{scenarios.CALLER}:5060"          # markup stripped
    assert first.src_device == "uac-gw" and first.dst_device == "sbc-edge"
    assert first.src_realms == ["Access"]
    assert first.leg == 0 and first.link_type == "vlan 100"
    assert first.time_known and first.timestamp > 0

    # The frame number is the row number in the export, media rows included, so a
    # finding can be looked up on the page it came from.
    assert [m.frame for m in trace.messages][:3] == [1, 2, 3]
    assert [r.frame for r in trace.media_reports][:1] == [9]

    # One SBC, two addresses, and the export is what says so.
    sbc = next(d for d in trace.devices if d.name == "sbc-edge")
    assert set(sbc.addresses) == {scenarios.SBC_OUT, scenarios.SBC_IN}
    assert sbc.kind == "SBC"
    assert len(calls) == 1, "one Call-ID across both legs"


def test_a_b2bua_leg_is_its_own_view_of_the_dialog():
    """Two hops sharing a Call-ID and both tags must not be read as one dialog.

    Merged, the offer on one leg pairs with the answer on the other and every
    forwarded request reads as CSeq reuse — which is what this asserts is gone.
    """
    path, _ = scenarios.ocom_export()
    _, calls, _, findings = analyse(path)
    call = calls[0]

    assert {d.leg for d in call.dialogs} == {0, 1}
    for d in call.dialogs:
        assert len(d.exchanges) == 1
        ex = d.negotiated
        assert ex is not None and ex.complete
        # Each leg's offer and answer are that leg's own addresses.
        assert ex.offer.leg == d.leg and ex.answer.leg == d.leg

    assert findings == []


def test_probe_reported_media_is_not_treated_as_a_packet_capture():
    path, _ = scenarios.ocom_bad_media()
    trace, _, streams, findings = analyse(path)

    assert streams == [], "a summary is not a stream of packets"
    assert not [f for f in findings if f.check_id.startswith("RTP-")]
    assert {f.check_id for f in findings} == {
        "MEDIA-REPORTED-LOSS", "MEDIA-REPORTED-JITTER", "MEDIA-REPORTED-MOS-LOW"}

    # One finding per stream, not one per START and END row.
    for check in ("MEDIA-REPORTED-LOSS", "MEDIA-REPORTED-JITTER"):
        assert len([f for f in findings if f.check_id == check]) == 1

    bad = next(r for r in trace.media_reports if r.mos is not None)
    assert bad.loss_ratio == 0.032 and bad.jitter_avg_ms == 48.0
    assert bad.codecs == ["PCMA (8)"] and bad.reporter == "OCOM-RTP-PROBE"


def test_leg_and_device_counts_are_per_call_not_per_trace():
    """One export, three calls, three different topologies — and none assumed."""
    path, _ = scenarios.ocom_varied_topologies()
    trace, calls, _, findings = analyse(path)
    by_id = {c.call_id: c for c in calls}

    direct = by_id["ocom-direct@example.net"]
    b2bua = by_id["ocom-1@example.net"]
    chained = by_id["ocom-chain@example.net"]

    assert (direct.legs, len(direct.devices)) == ([0], 2)
    assert (b2bua.legs, len(b2bua.devices)) == ([0, 1], 3)
    # Leg numbers are the source's: they need not start at zero or be contiguous.
    assert (chained.legs, len(chained.devices)) == ([7, 8, 9, 10], 5)

    # One dialog per leg, so a four-hop call has four — not one merged view.
    for call in (direct, b2bua, chained):
        assert {d.leg for d in call.dialogs} == set(call.legs)
        assert call.outcome == "answered"

    # The trace's column list is the union, and every call's path is a subset.
    assert len(trace.device_order) == 8
    for call in calls:
        assert set(call.devices) <= set(trace.device_order)

    assert findings == []


def test_a_source_without_legs_still_reads_as_one_dialog():
    """Older exports omit legid; the model must fall back, not fail."""
    from analyzer.model import _dialog_key
    path, _ = scenarios.clean_call()
    _, calls, _, _ = analyse(path)
    call = calls[0]
    assert len(call.dialogs) == 1 and call.dialogs[0].leg is None
    assert call.legs == [] and call.devices == []
    assert _dialog_key(call.messages[-1])[1] is None


def test_ipv6_hosts_compare_bracketed_or_not():
    """A Via sent-by keeps the wire form; an endpoint does not. They are one host."""
    from analyzer.checks.routing import _host_of
    assert _host_of("[2001:db8:d:6::1]:5060") == "2001:db8:d:6::1"
    assert _host_of("[2001:db8:d:6::1]") == "2001:db8:d:6::1"
    assert _host_of("10.0.0.1:5060") == "10.0.0.1"
    assert _host_of("10.0.0.1") == "10.0.0.1"


def test_an_answer_may_pick_any_offered_telephone_event():
    """Two clock rates offered, one kept: RFC 4733 working, not a mismatch."""
    from analyzer.sdp import parse
    offer = parse("v=0\no=- 1 0 IN IP4 1.1.1.1\ns=-\nc=IN IP4 1.1.1.1\nt=0 0\n"
                  "m=audio 5000 RTP/AVP 111 8 110 106\n"
                  "a=rtpmap:111 opus/48000/2\na=rtpmap:8 PCMA/8000\n"
                  "a=rtpmap:110 telephone-event/48000\n"
                  "a=rtpmap:106 telephone-event/8000\n")
    assert offer.audio().telephone_event_pts == {110, 106}


def test_every_check_id_exists_in_the_knowledge_base():
    from analyzer.checks.base import REGISTRY
    kb = requires_knowledge_base()
    unknown = set(REGISTRY) - set(kb.checks)
    assert not unknown, f"checks with no catalog entry: {sorted(unknown)}"


def test_call_id_groups_are_classified_by_kind():
    """A Call-ID group is not a call: only the INVITE dialog counts as one."""
    path, _ = scenarios.busy_trunk()
    _, calls, _, _ = analyse(path)
    kinds = {c.call_id: c.kind for c in calls}
    assert kinds == {
        "trunk-call-1@example.net": "call",
        "ping-0@example.net": "keepalive",
        "ping-1@example.net": "keepalive",
        "ping-2@example.net": "keepalive",
        "trunk-reg-1@example.net": "registration",
        "trunk-notify-1@example.net": "subscription",
        "trunk-old-1@example.net": "orphan",
    }
    assert sum(1 for c in calls if c.is_call) == 1


def test_census_reconciles_the_two_call_counts():
    """The number a VoIP analyser reports, next to the raw Call-ID count."""
    from analyzer.report import Report
    knowledge = requires_knowledge_base()
    path, _ = scenarios.busy_trunk()
    _, calls, streams, findings = analyse(path)
    report = Report(source="t", calls=calls, streams=streams, findings=findings,
                    knowledge=knowledge)
    census = report.census()
    assert census["calls"] == 1
    assert census["call_ids"] == len(calls) == 7
    assert census["by_kind"] == {"call": 1, "orphan": 1, "registration": 1,
                                 "subscription": 1, "keepalive": 3}
    # The exported report has to carry both numbers, or an export disagrees with
    # the screen it was taken from.
    import json
    payload = json.loads(report.to_json())
    assert payload["counts"]["calls"] == 1
    assert {c["kind"] for c in payload["calls"]} == set(census["by_kind"])


def _vlan_pcap(path: pathlib.Path, vlans: list[list[int]]) -> pathlib.Path:
    """One SIP datagram per entry; each entry is its frame's VLAN tag stack.

    An empty stack writes an untagged Ethernet frame. Fixed MACs and documentation
    addresses, as tests/builder.py uses.
    """
    from scapy.all import IP, UDP, Dot1Q, Ether, Raw, wrpcap

    from tests import builder
    packets = []
    for i, stack in enumerate(vlans):
        raw = builder.request("OPTIONS", f"trunk-{i}@{builder.CALLER}",
                              branch=f"z9hG4bK-trunk-{i}", cseq=i + 1)
        frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        for vid in stack:
            frame = frame / Dot1Q(vlan=vid)
        pkt = (frame / IP(src=builder.CALLER, dst=builder.CALLEE, id=2000 + i)
               / UDP(sport=5060, dport=5060)
               / Raw(raw.replace("\n", "\r\n").encode()))
        pkt.time = 1_700_000_000.0 + i
        packets.append(pkt)
    wrpcap(str(path), packets)
    return path


def _mixed_link_notes(trace) -> list[str]:
    return [n for n in trace.notes if n.startswith("mixed link layers")]


def test_one_trunk_with_several_vlans_is_one_capture_point(tmp_path):
    """An SBC's access leg on VLAN 100 and core leg on VLAN 200, seen on one trunk."""
    trace = readers.read_pcap(_vlan_pcap(tmp_path / "trunk.pcap", [[100], [200]]))
    assert [m.link_type for m in trace.messages] == ["vlan 100", "vlan 200"]
    assert _mixed_link_notes(trace) == []


def test_qinq_and_single_tags_on_one_trunk_are_one_capture_point(tmp_path):
    trace = readers.read_pcap(_vlan_pcap(tmp_path / "qinq.pcap", [[10, 20], [100]]))
    assert [m.link_type for m in trace.messages] == ["vlan 10 (qinq 10/20)", "vlan 100"]
    assert _mixed_link_notes(trace) == []


def test_untagged_and_tagged_frames_are_still_a_mixed_capture(tmp_path):
    trace = readers.read_pcap(_vlan_pcap(tmp_path / "mixed.pcap", [[], [100]]))
    assert [m.link_type for m in trace.messages] == ["ethernet", "vlan 100"]
    assert _mixed_link_notes(trace) == [
        "mixed link layers in one capture (ethernet, vlan 100): "
        "this usually means two capture points were merged"]


def _ngrep_sip(n: int) -> str:
    return (f"OPTIONS sip:b@5.6.7.8 SIP/2.0\nVia: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK{n}\n"
            f"From: <sip:a@1.2.3.4>;tag=1\nTo: <sip:b@5.6.7.8>\nCall-ID: ngrep-{n}\n"
            f"CSeq: 1 OPTIONS\nMax-Forwards: 70\nContent-Length: 0\n\n")


def _ngrep_log(tmp_path: pathlib.Path, text: str):
    path = tmp_path / "sngrep.log"
    path.write_text(text)
    return readers.read(path)


def test_ngrep_dated_header_line_sets_time_and_endpoints(tmp_path):
    """The format from the NGREP_HDR comment itself: date, time, both endpoints."""
    trace = _ngrep_log(tmp_path, "U 2024/01/01 10:00:00.123456 1.2.3.4:5060 -> 5.6.7.8:5060\n"
                       + _ngrep_sip(1))
    assert len(trace.messages) == 1
    m = trace.messages[0]
    assert abs(m.timestamp - datetime(2024, 1, 1, 10, 0, 0, 123456).timestamp()) < 1e-5
    assert m.time_known
    assert (m.src, m.dst) == ("1.2.3.4:5060", "5.6.7.8:5060")


def test_ngrep_undated_header_line_is_seconds_since_midnight(tmp_path):
    trace = _ngrep_log(tmp_path, "U 10:00:00.123456 1.2.3.4:5060 -> 5.6.7.8:5060\n"
                       + _ngrep_sip(1))
    assert len(trace.messages) == 1
    assert abs(trace.messages[0].timestamp - 36000.123456) < 1e-5


def test_ngrep_t_lines_are_read_too(tmp_path):
    trace = _ngrep_log(tmp_path, "T 2024/01/01 10:00:00.5 1.2.3.4:5060 -> 5.6.7.8:5060\n"
                       + _ngrep_sip(1))
    assert len(trace.messages) == 1
    assert abs(trace.messages[0].timestamp
               - datetime(2024, 1, 1, 10, 0, 0, 500000).timestamp()) < 1e-5


def test_ngrep_headers_keep_each_message_its_own_time_and_direction(tmp_path):
    trace = _ngrep_log(tmp_path, "U 10:00:00.250000 1.2.3.4:5060 -> 5.6.7.8:5060\n"
                       + _ngrep_sip(1)
                       + "U 10:00:01.750000 5.6.7.8:5060 -> 1.2.3.4:5060\n" + _ngrep_sip(2))
    assert [round(m.timestamp, 6) for m in trace.messages] == [36000.25, 36001.75]
    assert [m.src for m in trace.messages] == ["1.2.3.4:5060", "5.6.7.8:5060"]


def test_ngrep_header_times_count_as_timed(tmp_path):
    trace = _ngrep_log(tmp_path, "U 10:00:00.123456 1.2.3.4:5060 -> 5.6.7.8:5060\n"
                       + _ngrep_sip(1))
    assert not [n for n in trace.notes if "no timestamps found" in n], trace.notes


# ---------------------------------------------------------------- IPv6 retransmissions
# Every packet of an IPv6 flow carries the same flow label (RFC 6437 section 2),
# so it cannot serve as a packet identity the way IPv4's identification field
# can: a retransmission is not a capture duplicate just because its label repeats.
_V6_T0 = 1_700_000_000.0
_V6_TIMER_A = [0.0, 0.5, 1.5, 3.5]     # RFC 3261 17.1.1.2: T1, 2*T1, 4*T1


def _v6_invite(host: str) -> bytes:
    return (f"INVITE sip:bob@example.net SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {host}:5060;branch=z9hG4bK-v6ret\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:alice@example.net>;tag=aaa\r\n"
            f"To: <sip:bob@example.net>\r\n"
            f"Call-ID: v6-ret@example.net\r\n"
            f"CSeq: 1 INVITE\r\n"
            f"Contact: <sip:alice@{host}>\r\n"
            f"Content-Length: 0\r\n\r\n").encode()


def _v6_packet(t: float, fl: int = 0x12345, ident: int | None = None):
    from scapy.all import IP, UDP, Ether, IPv6, Raw

    ip = (IPv6(src="2001:db8::1", dst="2001:db8::2", fl=fl) if ident is None
          else IP(src="192.0.2.1", dst="198.51.100.20", id=ident))
    host = "[2001:db8::1]" if ident is None else "192.0.2.1"
    pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / ip
           / UDP(sport=5060, dport=5060) / Raw(_v6_invite(host)))
    pkt.time = _V6_T0 + t
    return pkt


def _retransmissions(calls) -> int:
    return sum(len(t.retransmissions) for c in calls for t in c.transactions)


def test_ipv6_retransmissions_with_a_flow_label_count_as_retransmissions(tmp_path):
    """Four sends at the RFC 3261 timer A spacing share one flow label: they are
    retransmissions, not four copies of one packet."""
    from scapy.all import wrpcap

    path = tmp_path / "v6-retrans.pcap"
    wrpcap(str(path), [_v6_packet(t) for t in _V6_TIMER_A])
    trace, calls, _, findings = analyse(path)

    assert not [m for m in trace.messages if m.is_duplicate]
    assert _retransmissions(calls) == 3
    ids = {f.check_id for f in findings}
    assert "SIP-INVITE-RETRANSMIT-NO-RESPONSE" in ids
    assert "CAP-DUPLICATE-FRAMES" not in ids


def test_ipv6_with_flow_label_zero_behaves_the_same(tmp_path):
    from scapy.all import wrpcap

    path = tmp_path / "v6-fl0.pcap"
    wrpcap(str(path), [_v6_packet(t, fl=0) for t in _V6_TIMER_A])
    trace, calls, _, findings = analyse(path)

    assert not [m for m in trace.messages if m.is_duplicate]
    assert _retransmissions(calls) == 3
    assert "SIP-INVITE-RETRANSMIT-NO-RESPONSE" in {f.check_id for f in findings}


def test_a_mirrored_ipv6_frame_is_still_a_capture_duplicate(tmp_path):
    """The same bytes twice within DUPLICATE_WINDOW stays a capture artefact."""
    from scapy.all import wrpcap

    path = tmp_path / "v6-mirror.pcap"
    wrpcap(str(path), [_v6_packet(0.0), _v6_packet(0.002)])
    trace, calls, _, findings = analyse(path)

    assert len([m for m in trace.messages if m.is_duplicate]) == 1
    assert "CAP-DUPLICATE-FRAMES" in {f.check_id for f in findings}
    assert _retransmissions(calls) == 0


def test_ipv4_retransmissions_are_unchanged(tmp_path):
    """Over IPv4 each send gets a fresh identification field, so behaviour is as before."""
    from scapy.all import wrpcap

    path = tmp_path / "v4-retrans.pcap"
    wrpcap(str(path), [_v6_packet(t, ident=100 + i) for i, t in enumerate(_V6_TIMER_A)])
    _, calls, _, findings = analyse(path)

    assert _retransmissions(calls) == 3
    assert "SIP-INVITE-RETRANSMIT-NO-RESPONSE" in {f.check_id for f in findings}


def test_a_mirrored_ipv4_frame_is_still_a_capture_duplicate(tmp_path):
    from scapy.all import wrpcap

    path = tmp_path / "v4-mirror.pcap"
    wrpcap(str(path), [_v6_packet(0.0, ident=500), _v6_packet(0.002, ident=500)])
    _, _, _, findings = analyse(path)

    assert "CAP-DUPLICATE-FRAMES" in {f.check_id for f in findings}


# ---------------------------------------------------------------- SIP over TCP
T0 = 1_700_000_000.0


def _crlf(message: str) -> bytes:
    """Encode a builder template as a stream transport carries it.

    CRLF line ends, with Content-Length corrected to the body's size in octets:
    the templates count it with LF ends, which is exactly the short count that
    broke framing.
    """
    crlf = message.replace("\n", "\r\n")
    head, sep, body = crlf.partition("\r\n\r\n")
    head = re.sub(r"Content-Length: \d+", f"Content-Length: {len(body)}", head)
    return (head + sep + body).encode()


def _big_invite(call_id: str) -> str:
    """An INVITE whose body pushes it past one TCP segment (1,460 bytes)."""
    pad = "".join(f"a=x-pad{i}:{'z' * 60}\n" for i in range(25))
    body = (f"v=0\no=- 1 1 IN IP4 {builder.CALLER}\ns=-\nc=IN IP4 {builder.CALLER}\n"
            f"t=0 0\nm=audio 4000 RTP/AVP 0\na=rtpmap:0 PCMU/8000\n{pad}a=sendrecv\n")
    return builder.invite(call_id, body=body)


def _tcp_cut(data: bytes, size: int = 1460, seq0: int = 1000) -> list[tuple[int, bytes]]:
    """The stream as (seq, bytes) segments of at most `size` bytes."""
    return [(seq0 + i, data[i:i + size]) for i in range(0, len(data), size)]


def _tcp_segment(src: str, dst: str, data: bytes, seq: int, t: float,
                 ip_id: int = 1):
    from scapy.all import IP, TCP, Ether, Raw
    pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
           / IP(src=src, dst=dst, id=ip_id)
           / TCP(sport=5060, dport=5060, flags="PA", seq=seq) / Raw(data))
    pkt.time = t
    return pkt


def _tcp_pcap(tmp_path: pathlib.Path, name: str, packets: list):
    from scapy.all import wrpcap
    path = tmp_path / name
    wrpcap(str(path), packets)
    return readers.read_pcap(path)


def _tcp_stream(builder_messages: list[str], size: int = 1460):
    """One direction's stream: each message CRLF-encoded, concatenated, cut into segments."""
    return _tcp_cut(b"".join(_crlf(m) for m in builder_messages), size=size)


def test_a_large_invite_in_two_tcp_segments_is_read_whole(tmp_path):
    """A 2,000-byte INVITE arrives as two segments; the second one completes it."""
    segments = _tcp_stream([_big_invite("tcp-big")])
    assert len(segments) == 2
    packets = [_tcp_segment(builder.CALLER, builder.CALLEE, d, s, T0 + i * 0.01,
                            ip_id=2000 + i) for i, (s, d) in enumerate(segments)]
    trace = _tcp_pcap(tmp_path, "tcp-order.pcap", packets)
    assert [m.method for m in trace.messages] == ["INVITE"]
    m = trace.messages[0]
    assert m.transport == "TCP" and "m=audio 4000" in m.body and "a=sendrecv" in m.body
    assert m.frame == 2 and abs(m.timestamp - (T0 + 0.01)) < 1e-6


def test_tcp_segments_captured_out_of_order_are_put_back_in_sequence(tmp_path):
    """The segments arrive in reverse; the stream is rebuilt in sequence order."""
    segments = _tcp_stream([_big_invite("tcp-ooo")])
    packets = [_tcp_segment(builder.CALLER, builder.CALLEE, d, s, T0 + i * 0.01,
                            ip_id=3000 + i) for i, (s, d) in enumerate(reversed(segments))]
    trace = _tcp_pcap(tmp_path, "tcp-reversed.pcap", packets)
    assert [m.method for m in trace.messages] == ["INVITE"]
    assert "m=audio 4000" in trace.messages[0].body
    assert trace.messages[0].frame == 2        # the later-captured first segment


def test_a_retransmitted_tcp_segment_is_used_once(tmp_path):
    segments = _tcp_stream([_big_invite("tcp-rtx")])
    (s1, d1), (s2, d2) = segments
    packets = [_tcp_segment(builder.CALLER, builder.CALLEE, d1, s1, T0, ip_id=4001),
               _tcp_segment(builder.CALLER, builder.CALLEE, d1, s1, T0 + 0.2, ip_id=4001),
               _tcp_segment(builder.CALLER, builder.CALLEE, d2, s2, T0 + 0.3, ip_id=4002)]
    trace = _tcp_pcap(tmp_path, "tcp-retransmitted.pcap", packets)
    assert len(trace.messages) == 1
    assert "m=audio 4000" in trace.messages[0].body
    assert not [n for n in trace.notes if "duplicated" in n]


def test_a_missing_tcp_segment_gives_a_note_and_keeps_the_messages_before_it(tmp_path):
    """The second segment never made it into the capture: one note, no joining."""
    segments = _tcp_stream([builder.request("OPTIONS", "tcp-gap-1", cseq=1),
                            _big_invite("tcp-gap-2")], size=800)
    assert len(segments) >= 3
    kept = [seg for i, seg in enumerate(segments) if i != 1]
    packets = [_tcp_segment(builder.CALLER, builder.CALLEE, d, s, T0 + i * 0.01,
                            ip_id=5000 + i) for i, (s, d) in enumerate(kept)]
    trace = _tcp_pcap(tmp_path, "tcp-gap.pcap", packets)
    notes = [n for n in trace.notes if n.startswith("TCP data missing")]
    assert len(notes) == 1
    assert builder.CALLER in notes[0] and builder.CALLEE in notes[0]
    assert "tcp-gap-1" in [m.call_id for m in trace.messages]
    assert "tcp-gap-2" not in [m.call_id for m in trace.messages]


def test_the_message_after_a_tcp_body_is_not_swallowed(tmp_path):
    """Content-Length counts octets, so the next message starts right after the body."""
    first = _crlf(_big_invite("tcp-sdp"))
    second = _crlf(builder.request("OPTIONS", "tcp-next", cseq=2))
    packets = [_tcp_segment(builder.CALLER, builder.CALLEE, first, 1000, T0, ip_id=6001),
               _tcp_segment(builder.CALLER, builder.CALLEE, second, 1000 + len(first),
                            T0 + 0.01, ip_id=6002)]
    trace = _tcp_pcap(tmp_path, "tcp-after-body.pcap", packets)
    assert [(m.method, m.call_id) for m in trace.messages] == [
        ("INVITE", "tcp-sdp"), ("OPTIONS", "tcp-next")]
    assert "m=audio 4000" in trace.messages[0].body


def test_two_tcp_messages_in_one_segment_are_both_read(tmp_path):
    stream = _tcp_stream([builder.request("OPTIONS", "tcp-a", cseq=1),
                          builder.request("OPTIONS", "tcp-b", cseq=2)])[0][1]
    trace = _tcp_pcap(tmp_path, "tcp-two.pcap",
                      [_tcp_segment(builder.CALLER, builder.CALLEE, stream, 1000, T0)])
    assert [m.call_id for m in trace.messages] == ["tcp-a", "tcp-b"]
    assert [m.transport for m in trace.messages] == ["TCP", "TCP"]


# ---------------------------------------------------------------- IP fragments
def _fragment_pcap(path: pathlib.Path, *, reversed_order: bool = False,
                   drop_first: bool = False, drop_last: bool = False) -> pathlib.Path:
    """One large INVITE over UDP, sent as IPv4 fragments via scapy's fragment().

    The SDP carries a video line and padding past the first fragment, so a
    datagram read un-reassembled loses the m=video line. Fixed MACs and
    documentation addresses, as tests/builder.py uses.
    """
    from scapy.all import IP, UDP, Ether, Raw, fragment, wrpcap

    from tests import builder
    pad = "".join(f"a=x-pad{i}:{'z' * 60}\n" for i in range(25))
    body = (f"v=0\no=- 1 1 IN IP4 {builder.CALLER}\ns=-\nc=IN IP4 {builder.CALLER}\n"
            f"t=0 0\nm=audio 40000 RTP/AVP 0 8\n" + pad
            + "m=video 4002 RTP/AVP 96\na=rtpmap:96 H264/90000\n")
    raw = builder.invite(f"frag-1@{builder.CALLEE}", body=body)
    big = (IP(src=builder.CALLER, dst=builder.CALLEE, id=4242)
           / UDP(sport=5060, dport=5060) / Raw(raw.replace("\n", "\r\n").encode()))
    frags = [Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / f
             for f in fragment(big, fragsize=1400)]
    for i, f in enumerate(frags):
        f.time = 1_700_000_000.0 + i * 0.001
    if reversed_order:
        frags.reverse()
    if drop_first:
        frags = frags[1:]
    if drop_last:
        frags = frags[:-1]
    wrpcap(str(path), frags)
    return path


def _fragment_notes(trace) -> list[str]:
    return [n for n in trace.notes
            if n.startswith("message incomplete: IP fragment missing")]


def test_two_fragments_in_order_reassemble_into_one_message(tmp_path):
    path = _fragment_pcap(tmp_path / "frag.pcap")
    trace, calls, _, findings = analyse(path)
    assert len(trace.messages) == 1
    m = trace.messages[0]
    assert m.method == "INVITE"
    assert m.body.startswith("v=0")
    assert "m=video" in m.body and "a=x-pad24" in m.body     # past the first fragment
    assert m.frame == 2                  # the fragment that completed the datagram
    assert _fragment_notes(trace) == [] and trace.fragments_missing == 0
    assert "CAP-IP-FRAGMENT-MISSING" not in {f.check_id for f in findings}


def test_fragments_captured_in_reverse_still_reassemble(tmp_path):
    path = _fragment_pcap(tmp_path / "frag.pcap", reversed_order=True)
    trace, _, _, _ = analyse(path)
    assert len(trace.messages) == 1
    m = trace.messages[0]
    assert "m=video" in m.body and "a=x-pad24" in m.body
    assert _fragment_notes(trace) == [] and trace.fragments_missing == 0


def test_a_missing_last_fragment_keeps_what_was_captured_and_warns(tmp_path):
    path = _fragment_pcap(tmp_path / "frag.pcap", drop_last=True)
    trace, _, _, findings = analyse(path)
    assert len(trace.messages) == 1
    assert "m=video" not in trace.messages[0].body           # the second fragment is gone
    notes = _fragment_notes(trace)
    assert len(notes) == 1
    assert scenarios.CALLER in notes[0] and scenarios.CALLEE in notes[0]
    assert trace.fragments_missing == 1
    loss = [f for f in findings if f.check_id == "CAP-IP-FRAGMENT-MISSING"]
    assert len(loss) == 1
    assert "packet loss" in loss[0].detail.lower() and "1" in loss[0].detail


def test_a_missing_first_fragment_warns_too(tmp_path):
    path = _fragment_pcap(tmp_path / "frag.pcap", drop_first=True)
    trace, calls, _, findings = analyse(path)
    assert trace.messages == [], "without offset 0 there is no UDP header to read"
    assert len(_fragment_notes(trace)) == 1 and trace.fragments_missing == 1
    assert "CAP-IP-FRAGMENT-MISSING" in {f.check_id for f in findings}


def test_fragmented_and_unfragmented_messages_read_alike(tmp_path):
    """The same INVITE whole and in fragments must parse to the same message."""
    whole = _fragment_pcap(tmp_path / "whole.pcap")
    frags = _fragment_pcap(tmp_path / "frag.pcap")
    a = readers.read_pcap(whole).messages[0]
    b = readers.read_pcap(frags).messages[0]
    assert a.raw == b.raw
    # The reassembled message is timed at the fragment that completed it.
    assert (a.src, a.dst) == (b.src, b.dst)


# ---------------------------------------------------------------- extension methods
# RFC 3261 section 25.1: Method = INVITEm / ... / extension-method, and
# extension-method = token, so a request line with any method is SIP. The UDP
# reader used to gate on a fixed list of four-byte method prefixes and dropped
# the rest whole, before parse ever saw them.
def _udp_pcap(tmp_path: pathlib.Path, name: str, payloads: list[bytes]) -> pathlib.Path:
    """One untagged Ethernet frame per payload, CALLER -> CALLEE on 5060.

    Fixed MACs and documentation addresses, as tests/builder.py uses.
    """
    from scapy.all import IP, UDP, Ether, Raw, wrpcap

    packets = []
    for i, payload in enumerate(payloads):
        pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
               / IP(src=builder.CALLER, dst=builder.CALLEE, id=7000 + i)
               / UDP(sport=5060, dport=5060) / Raw(payload))
        pkt.time = 1_700_000_000.0 + i * 0.001
        packets.append(pkt)
    path = tmp_path / name
    wrpcap(str(path), packets)
    return path


def test_an_extension_method_request_is_read(tmp_path):
    """A complete SERVICE request is read whole, whatever its method."""
    raw = builder.request("SERVICE", "service@example.net", cseq=1)
    trace = readers.read_pcap(_udp_pcap(tmp_path, "service.pcap",
                                        [raw.replace("\n", "\r\n").encode()]))
    assert [m.method for m in trace.messages] == ["SERVICE"]
    assert trace.messages[0].call_id == "service@example.net"
    assert trace.messages[0].is_request


def test_extension_methods_read_alongside_known_ones(tmp_path):
    """A capture mixing known methods and extension methods reads them all."""
    payloads = [builder.request("REPLACES", "ext-1@example.net", cseq=1),
                builder.request("OPTIONS", "ka-1@example.net", cseq=1)]
    trace = readers.read_pcap(_udp_pcap(
        tmp_path, "mix.pcap", [p.replace("\n", "\r\n").encode() for p in payloads]))
    assert [m.method for m in trace.messages] == ["REPLACES", "OPTIONS"]


def test_a_payload_that_is_not_sip_is_still_ignored(tmp_path):
    """RTP-shaped payloads and noise stay out of the messages: the request-line
    check anchors on the payload's first octet, so a buried request line is not read."""
    service = (builder.request("SERVICE", "buried@example.net", cseq=1)
               .replace("\n", "\r\n").encode())
    payloads = [b"\x80\x00\x00\x01" + b"\xd5" * 120,   # an RTP-shaped payload
                b"HTTP/1.1 200 OK\r\n\r\n",
                b"\x00garbage\n" + service]            # does not start with the grammar
    trace = readers.read_pcap(_udp_pcap(tmp_path, "noise.pcap", payloads))
    assert trace.messages == []

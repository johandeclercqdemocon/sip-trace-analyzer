"""Every scenario plants known faults; the analyser must find exactly those."""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from analyzer import model, readers  # noqa: E402
from analyzer.checks import Context, run_all  # noqa: E402
from tests import scenarios  # noqa: E402


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

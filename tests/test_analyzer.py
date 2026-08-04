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


def test_every_check_id_exists_in_the_knowledge_base():
    from analyzer.checks.base import REGISTRY
    kb = requires_knowledge_base()
    unknown = set(REGISTRY) - set(kb.checks)
    assert not unknown, f"checks with no catalog entry: {sorted(unknown)}"

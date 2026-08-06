"""Synthetic traces. Each returns (path, expected_check_ids)."""
from __future__ import annotations

import pathlib

from .builder import (
    CALLEE,
    CALLER,
    PROXY,
    Builder,
    invite,
    ocom_device,
    ocom_media,
    ocom_sip,
    request,
    response,
    sdp,
    write_ocom,
)

DATA = pathlib.Path(__file__).parent / "data"

CALLER_MEDIA, CALLEE_MEDIA = 40000, 40002


def clean_call(path: pathlib.Path = DATA / "clean.pcap") -> tuple[pathlib.Path, set[str]]:
    """A textbook call: nothing should be reported."""
    b = Builder()
    cid = "clean-1@example.net"
    offer = sdp(CALLER, CALLER_MEDIA)
    answer = sdp(CALLEE, CALLEE_MEDIA)
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=offer))
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag=""))
    b.sip(0.20, CALLEE, CALLER, response(180, "Ringing", cid))
    b.sip(2.00, CALLEE, CALLER, response(200, "OK", cid, body=answer,
                                         contact=f"<sip:bob@{CALLEE}>"))
    b.sip(2.05, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1"))
    b.rtp(2.10, CALLER, CALLEE, CALLER_MEDIA, CALLEE_MEDIA, ssrc=0xAAAA, count=250)
    b.rtp(2.10, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=250)
    b.sip(7.20, CALLER, CALLEE, request("BYE", cid, cseq=2, branch="z9hG4bK-bye-1"))
    b.sip(7.25, CALLEE, CALLER, response(200, "OK", cid, cseq=2, method="BYE",
                                         branch="z9hG4bK-bye-1"))
    return b.write(path), set()


def missing_ack(path: pathlib.Path = DATA / "missing_ack.pcap") -> tuple[pathlib.Path, set[str]]:
    """The 200 OK is never ACKed, so the UAS retransmits it on Timer G."""
    b = Builder()
    cid = "noack-1@example.net"
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=sdp(CALLER, CALLER_MEDIA)))
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag=""))
    answer = sdp(CALLEE, CALLEE_MEDIA)
    for t in (1.0, 1.5, 2.5, 4.5, 8.5):
        b.sip(t, CALLEE, CALLER, response(200, "OK", cid, body=answer,
                                          contact=f"<sip:bob@{CALLEE}>"))
    return b.write(path), {"SIP-ACK-MISSING", "SIP-2XX-RETRANSMIT", "RTP-NO-STREAM"}


def nat_private(path: pathlib.Path = DATA / "nat.pcap") -> tuple[pathlib.Path, set[str]]:
    """A UA behind NAT advertising private addresses in Contact, Via and SDP."""
    b = Builder()
    cid = "nat-1@example.net"
    priv = "192.168.1.50"
    offer = sdp(priv, CALLER_MEDIA)
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=offer, contact=f"<sip:alice@{priv}>",
                                      via_host=priv))
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag="", via_host=priv))
    b.sip(1.0, CALLEE, CALLER, response(200, "OK", cid, body=sdp(CALLEE, CALLEE_MEDIA),
                                        contact=f"<sip:bob@{CALLEE}>", via_host=priv))
    b.sip(1.05, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1",
                                        via_host=priv))
    b.rtp(1.10, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=200)
    b.sip(6.0, CALLER, CALLEE, request("BYE", cid, cseq=2, branch="z9hG4bK-bye-1",
                                       via_host=priv))
    b.sip(6.05, CALLEE, CALLER, response(200, "OK", cid, cseq=2, method="BYE",
                                         branch="z9hG4bK-bye-1", via_host=priv))
    return b.write(path), {"SIP-CONTACT-PRIVATE-ADDRESS", "SDP-PRIVATE-MEDIA-ADDRESS",
                           "SIP-VIA-RECEIVED-MISMATCH", "RTP-ONE-WAY"}


def codec_mismatch(path: pathlib.Path = DATA / "codec.pcap") -> tuple[pathlib.Path, set[str]]:
    """G.729-only offer rejected with 488."""
    b = Builder()
    cid = "codec-1@example.net"
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=sdp(CALLER, CALLER_MEDIA, codecs="18")))
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag=""))
    b.sip(0.30, CALLEE, CALLER, response(488, "Not Acceptable Here", cid))
    b.sip(0.32, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-inv-1"))
    return b.write(path), {"SDP-CODEC-MISMATCH"}


def auth_loop(path: pathlib.Path = DATA / "auth.pcap") -> tuple[pathlib.Path, set[str]]:
    """REGISTER challenged over and over: the credentials never satisfy the registrar."""
    b = Builder()
    cid = "auth-1@example.net"
    chal = ('WWW-Authenticate: Digest realm="example.net", '
            'nonce="{n}", algorithm=MD5\n')
    for i, t in enumerate((0.0, 0.5, 1.0, 1.5)):
        b.sip(t, CALLER, CALLEE,
              request("REGISTER", cid, cseq=i + 1, ttag="", branch=f"z9hG4bK-reg-{i}",
                      target=f"sip:{CALLEE}",
                      extra=("Authorization: Digest username=\"alice\", realm=\"example.net\", "
                             f"nonce=\"n{i}\", response=\"deadbeef\"\n" if i else "")))
        b.sip(t + 0.05, CALLEE, CALLER,
              response(401, "Unauthorized", cid, cseq=i + 1, method="REGISTER", ttag="",
                       branch=f"z9hG4bK-reg-{i}", extra=chal.format(n=f"n{i + 1}")))
    return b.write(path), {"SIP-AUTH-LOOP"}


def invite_timeout(path: pathlib.Path = DATA / "timeout.pcap") -> tuple[pathlib.Path, set[str]]:
    """INVITE retransmitted through the full Timer B ladder with no response at all."""
    b = Builder()
    cid = "timeout-1@example.net"
    body = sdp(CALLER, CALLER_MEDIA)
    for t in (0.0, 0.5, 1.5, 3.5, 7.5, 15.5, 31.5):
        b.sip(t, CALLER, CALLEE, invite(cid, body=body))
    return b.write(path), {"SIP-INVITE-RETRANSMIT-NO-RESPONSE", "SIP-NO-100-TRYING",
                           "SIP-TIMER-B-TIMEOUT"}


def packet_loss(path: pathlib.Path = DATA / "loss.pcap") -> tuple[pathlib.Path, set[str]]:
    """A good call whose media loses 8% of packets in one direction."""
    b = Builder()
    cid = "loss-1@example.net"
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=sdp(CALLER, CALLER_MEDIA)))
    b.sip(1.0, CALLEE, CALLER, response(200, "OK", cid, body=sdp(CALLEE, CALLEE_MEDIA),
                                        contact=f"<sip:bob@{CALLEE}>"))
    b.sip(1.05, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1"))
    drop = set(range(10, 250, 12))
    b.rtp(1.10, CALLER, CALLEE, CALLER_MEDIA, CALLEE_MEDIA, ssrc=0xAAAA, count=250)
    b.rtp(1.10, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=250, drop=drop)
    b.sip(7.0, CALLER, CALLEE, request("BYE", cid, cseq=2, branch="z9hG4bK-bye-1"))
    b.sip(7.05, CALLEE, CALLER, response(200, "OK", cid, cseq=2, method="BYE",
                                         branch="z9hG4bK-bye-1"))
    return b.write(path), {"RTP-SEQUENCE-GAP"}


def direction_mismatch(path: pathlib.Path = DATA / "direction.pcap"
                       ) -> tuple[pathlib.Path, set[str]]:
    """Offer says sendonly and the answer says sendonly too: nobody may receive."""
    b = Builder()
    cid = "dir-1@example.net"
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=sdp(CALLER, CALLER_MEDIA,
                                                    direction="sendonly")))
    b.sip(1.0, CALLEE, CALLER, response(200, "OK", cid, contact=f"<sip:bob@{CALLEE}>",
                                        body=sdp(CALLEE, CALLEE_MEDIA,
                                                 direction="sendonly")))
    b.sip(1.05, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1"))
    b.rtp(1.1, CALLER, CALLEE, CALLER_MEDIA, CALLEE_MEDIA, ssrc=0xAAAA, count=150)
    b.rtp(1.1, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=150)
    b.sip(6.0, CALLER, CALLEE, request("BYE", cid, cseq=2, branch="z9hG4bK-bye-1"))
    b.sip(6.05, CALLEE, CALLER, response(200, "OK", cid, cseq=2, method="BYE",
                                         branch="z9hG4bK-bye-1"))
    return b.write(path), {"SDP-DIRECTION-MISMATCH"}


def session_timer(path: pathlib.Path = DATA / "sesstimer.pcap"
                  ) -> tuple[pathlib.Path, set[str]]:
    """Session-Expires 90 negotiated, never refreshed, call dropped at expiry."""
    b = Builder()
    cid = "st-1@example.net"
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=sdp(CALLER, CALLER_MEDIA),
                                      extra="Session-Expires: 90;refresher=uac\n"
                                            "Supported: timer\n"))
    b.sip(1.0, CALLEE, CALLER, response(200, "OK", cid, body=sdp(CALLEE, CALLEE_MEDIA),
                                        contact=f"<sip:bob@{CALLEE}>",
                                        extra="Session-Expires: 90;refresher=uac\n"
                                              "Require: timer\n"))
    b.sip(1.05, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1"))
    # Media runs long enough for the absent RTCP to be a real observation.
    b.rtp(1.1, CALLER, CALLEE, CALLER_MEDIA, CALLEE_MEDIA, ssrc=0xAAAA, count=2200)
    b.rtp(1.1, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=2200)
    b.sip(92.0, CALLEE, CALLER, request("BYE", cid, cseq=2, caller=CALLEE, callee=CALLER,
                                        branch="z9hG4bK-bye-9",
                                        target=f"sip:alice@{CALLER}"))
    b.sip(92.05, CALLER, CALLEE, response(200, "OK", cid, cseq=2, method="BYE",
                                          caller=CALLEE, callee=CALLER,
                                          branch="z9hG4bK-bye-9"))
    return b.write(path), {"SIP-SESSION-TIMER-NO-REFRESH", "RTCP-ABSENT"}


def text_log(path: pathlib.Path = DATA / "asterisk.log") -> tuple[pathlib.Path, set[str]]:
    """An Asterisk-style text log carrying a call whose BYE is rejected 481."""
    cid = "textlog-1@example.net"
    blocks = [
        ("2026-08-04 09:15:01.100", CALLER, CALLEE,
         invite(cid, body=sdp(CALLER, CALLER_MEDIA))),
        ("2026-08-04 09:15:01.150", CALLEE, CALLER, response(100, "Trying", cid, ttag="")),
        ("2026-08-04 09:15:03.900", CALLEE, CALLER,
         response(200, "OK", cid, body=sdp(CALLEE, CALLEE_MEDIA),
                  contact=f"<sip:bob@{CALLEE}>")),
        ("2026-08-04 09:15:03.950", CALLER, CALLEE,
         request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1")),
        ("2026-08-04 09:20:11.000", CALLER, CALLEE,
         request("BYE", cid, cseq=2, branch="z9hG4bK-bye-1")),
        ("2026-08-04 09:20:11.050", CALLEE, CALLER,
         response(481, "Call/Transaction Does Not Exist", cid, cseq=2, method="BYE",
                  branch="z9hG4bK-bye-1")),
    ]
    out = []
    for ts, src, dst, raw in blocks:
        out.append(f"[{ts}] VERBOSE[1234] pjsip: <--- Transmitting SIP message --->")
        out.append(f"[{ts}] VERBOSE[1234] pjsip: {src}:5060 -> {dst}:5060")
        out.append(raw)
        out.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out))
    return path, {"SIP-IN-DIALOG-481"}


def nat_registration(path: pathlib.Path = DATA / "register.pcap"
                     ) -> tuple[pathlib.Path, set[str]]:
    """A NATed client granted a 3600s binding and then going quiet."""
    b = Builder()
    cid = "reg-1@example.net"
    priv = "192.168.1.50"
    reg = request("REGISTER", cid, cseq=1, ttag="", branch="z9hG4bK-reg-1",
                  target=f"sip:{CALLEE}", via_host=priv,
                  contact=f"<sip:alice@{priv}>", extra="Expires: 3600\n")
    b.sip(0.0, CALLER, CALLEE, reg)
    b.sip(0.05, CALLEE, CALLER,
          response(200, "OK", cid, cseq=1, method="REGISTER", ttag="reg", via_host=priv,
                   branch="z9hG4bK-reg-1",
                   contact=f"<sip:alice@{priv}>;expires=3600", extra="Expires: 3600\n"))
    # The private Contact is a genuine second fault: the registrar stores an
    # unreachable binding, so inbound calls fail even before the mapping expires.
    return b.write(path), {"SIP-REGISTER-EXPIRY-EXCEEDS-NAT", "SIP-VIA-RECEIVED-MISMATCH",
                           "SIP-CONTACT-PRIVATE-ADDRESS"}


def mirrored_capture(path: pathlib.Path = DATA / "mirrored.pcap"
                     ) -> tuple[pathlib.Path, set[str]]:
    """A healthy call captured on a mirrored port, so every frame appears twice.

    Without layer-3 duplicate detection this reads as a retransmission storm:
    doubled INVITEs and a doubled 200 OK with no ACK in between.
    """
    b = Builder()
    cid = "mirror-1@example.net"
    offer, answer = sdp(CALLER, CALLER_MEDIA), sdp(CALLEE, CALLEE_MEDIA)
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=offer), mirror=0.004)
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag=""), mirror=0.003)
    b.sip(0.20, CALLEE, CALLER, response(180, "Ringing", cid), mirror=0.005)
    b.sip(2.00, CALLEE, CALLER, response(200, "OK", cid, body=answer,
                                         contact=f"<sip:bob@{CALLEE}>"), mirror=0.004)
    b.sip(2.05, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1"),
          mirror=0.003)
    b.rtp(2.10, CALLER, CALLEE, CALLER_MEDIA, CALLEE_MEDIA, ssrc=0xAAAA, count=200)
    b.rtp(2.10, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=200)
    b.sip(6.20, CALLER, CALLEE, request("BYE", cid, cseq=2, branch="z9hG4bK-bye-1"),
          mirror=0.004)
    b.sip(6.25, CALLEE, CALLER, response(200, "OK", cid, cseq=2, method="BYE",
                                         branch="z9hG4bK-bye-1"), mirror=0.003)
    return b.write(path), {"CAP-DUPLICATE-FRAMES"}


def answer_without_contact(path: pathlib.Path = DATA / "nocontact.pcap"
                           ) -> tuple[pathlib.Path, set[str]]:
    """The 200 OK establishes a dialog but names no remote target."""
    b = Builder()
    cid = "nocontact-1@example.net"
    offer, answer = sdp(CALLER, CALLER_MEDIA), sdp(CALLEE, CALLEE_MEDIA)
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=offer))
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag=""))
    b.sip(1.00, CALLEE, CALLER, response(200, "OK", cid, body=answer))   # no Contact
    b.sip(1.05, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1"))
    b.rtp(1.10, CALLER, CALLEE, CALLER_MEDIA, CALLEE_MEDIA, ssrc=0xAAAA, count=200)
    b.rtp(1.10, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=200)
    b.sip(6.0, CALLER, CALLEE, request("BYE", cid, cseq=2, branch="z9hG4bK-bye-1"))
    b.sip(6.05, CALLEE, CALLER, response(200, "OK", cid, cseq=2, method="BYE",
                                         branch="z9hG4bK-bye-1"))
    return b.write(path), {"SIP-2XX-NO-CONTACT"}


def reinvite_before_answer(path: pathlib.Path = DATA / "earlyreinvite.pcap"
                           ) -> tuple[pathlib.Path, set[str]]:
    """A hold attempted during ringing with a re-INVITE instead of an UPDATE.

    The callee advertised UPDATE in its 180, so the correct method was available
    (RFC 3311 section 4); the UAC used the one RFC 3261 section 14.1 forbids here.
    """
    b = Builder()
    cid = "earlyre-1@example.net"
    offer = sdp(CALLER, CALLER_MEDIA)
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=offer))
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag=""))
    b.sip(0.20, CALLEE, CALLER, response(180, "Ringing", cid,
                                         extra="Allow: INVITE, ACK, BYE, CANCEL, UPDATE\n"))
    b.sip(1.00, CALLER, CALLEE, invite(cid, cseq=2, to_tag="bbb",
                                       branch="z9hG4bK-inv-2",
                                       body=sdp(CALLER, CALLER_MEDIA, codecs="0",
                                                version=1)))
    b.sip(3.00, CALLEE, CALLER, response(200, "OK", cid, body=sdp(CALLEE, CALLEE_MEDIA),
                                         contact=f"<sip:bob@{CALLEE}>"))
    b.sip(3.05, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1"))
    b.rtp(3.10, CALLER, CALLEE, CALLER_MEDIA, CALLEE_MEDIA, ssrc=0xAAAA, count=200)
    b.rtp(3.10, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=200)
    b.sip(8.0, CALLER, CALLEE, request("BYE", cid, cseq=3, branch="z9hG4bK-bye-1"))
    b.sip(8.05, CALLEE, CALLER, response(200, "OK", cid, cseq=3, method="BYE",
                                         branch="z9hG4bK-bye-1"))
    # The second INVITE never gets its own final response, which is the point:
    # a re-INVITE in an early dialog leaves both transactions unresolved.
    return b.write(path), {"SIP-REINVITE-IN-EARLY-DIALOG"}


def update_refused(path: pathlib.Path = DATA / "updatemissing.pcap"
                   ) -> tuple[pathlib.Path, set[str]]:
    """Hold during an early dialog, done correctly, against a peer that lacks UPDATE."""
    b = Builder()
    cid = "update-1@example.net"
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=sdp(CALLER, CALLER_MEDIA)))
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag=""))
    b.sip(0.20, CALLEE, CALLER, response(180, "Ringing", cid,
                                         extra="Allow: INVITE, ACK, BYE, CANCEL\n"))
    b.sip(1.00, CALLER, CALLEE, request("UPDATE", cid, cseq=2, branch="z9hG4bK-upd-1",
                                        body=sdp(CALLER, CALLER_MEDIA,
                                                 direction="sendonly", version=1)))
    b.sip(1.05, CALLEE, CALLER, response(405, "Method Not Allowed", cid, cseq=2,
                                         method="UPDATE", branch="z9hG4bK-upd-1"))
    b.sip(1.07, CALLER, CALLEE, request("ACK", cid, cseq=2, branch="z9hG4bK-upd-1"))
    b.sip(2.00, CALLEE, CALLER, response(200, "OK", cid, body=sdp(CALLEE, CALLEE_MEDIA),
                                         contact=f"<sip:bob@{CALLEE}>"))
    b.sip(2.05, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1"))
    b.rtp(2.10, CALLER, CALLEE, CALLER_MEDIA, CALLEE_MEDIA, ssrc=0xAAAA, count=200)
    b.rtp(2.10, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=200)
    b.sip(7.0, CALLER, CALLEE, request("BYE", cid, cseq=3, branch="z9hG4bK-bye-1"))
    b.sip(7.05, CALLEE, CALLER, response(200, "OK", cid, cseq=3, method="BYE",
                                         branch="z9hG4bK-bye-1"))
    # NOTE for whoever merges the non-INVITE-failure check: the 405 here will
    # also trip SIP-NON-INVITE-FAILED, so this set gains that id at merge time.
    return b.write(path), {"SIP-UPDATE-NOT-SUPPORTED"}


def require_rejected(path: pathlib.Path = DATA / "badextension.pcap"
                     ) -> tuple[pathlib.Path, set[str]]:
    """An INVITE demanding 100rel from a peer that does not implement it."""
    b = Builder()
    cid = "require-1@example.net"
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=sdp(CALLER, CALLER_MEDIA),
                                      extra="Require: precondition\n"))
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag=""))
    b.sip(0.30, CALLEE, CALLER, response(420, "Bad Extension", cid,
                                         extra="Unsupported: precondition\n"))
    b.sip(0.32, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-inv-1"))
    return b.write(path), {"SIP-REQUIRE-UNSUPPORTED"}


def redirect_ignored(path: pathlib.Path = DATA / "redirect.pcap"
                     ) -> tuple[pathlib.Path, set[str]]:
    """302 Moved Temporarily, and the UAC simply stops."""
    b = Builder()
    cid = "redirect-1@example.net"
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=sdp(CALLER, CALLER_MEDIA)))
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag=""))
    b.sip(0.30, CALLEE, CALLER, response(302, "Moved Temporarily", cid,
                                         contact=f"<sip:bob@{PROXY}>"))
    b.sip(0.32, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-inv-1"))
    # Nothing is sent to the offered target, and the capture runs on long enough
    # that its absence is a fact rather than an artefact of where it stops.
    b.sip(9.0, CALLER, CALLEE, request("OPTIONS", "ping-1@example.net", cseq=1, ttag="",
                                       branch="z9hG4bK-opt-9", target=f"sip:{CALLEE}"))
    b.sip(9.05, CALLEE, CALLER, response(200, "OK", "ping-1@example.net", cseq=1,
                                         method="OPTIONS", ttag="opt",
                                         branch="z9hG4bK-opt-9"))
    return b.write(path), {"SIP-REDIRECT-NOT-FOLLOWED"}


def early_media_on_180(path: pathlib.Path = DATA / "earlymedia.pcap"
                       ) -> tuple[pathlib.Path, set[str]]:
    """A gateway streaming an announcement behind 180 Ringing instead of 183.

    No provisional carries SDP, so there is no negotiated session for the media
    the caller is being sent — the classic silent-ringback complaint.
    """
    b = Builder()
    cid = "earlymedia-1@example.net"
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=sdp(CALLER, CALLER_MEDIA)))
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag=""))
    b.sip(0.20, CALLEE, CALLER, response(180, "Ringing", cid))
    # The gateway streams continuously from before the answer to after it, which
    # is what makes the early half unnegotiated rather than a separate stream.
    b.rtp(0.30, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=450)
    b.sip(4.00, CALLEE, CALLER, response(200, "OK", cid, body=sdp(CALLEE, CALLEE_MEDIA),
                                         contact=f"<sip:bob@{CALLEE}>"))
    b.sip(4.05, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1"))
    b.rtp(4.10, CALLER, CALLEE, CALLER_MEDIA, CALLEE_MEDIA, ssrc=0xAAAA, count=200)
    b.sip(9.0, CALLER, CALLEE, request("BYE", cid, cseq=2, branch="z9hG4bK-bye-1"))
    b.sip(9.05, CALLEE, CALLER, response(200, "OK", cid, cseq=2, method="BYE",
                                         branch="z9hG4bK-bye-1"))
    return b.write(path), {"SIP-EARLY-MEDIA-UNNEGOTIATED"}


def rel100_broken(path: pathlib.Path = DATA / "rel100.pcap") -> tuple[pathlib.Path, set[str]]:
    """100rel done three ways wrong in one capture.

    The 183 demands 100rel with no RSeq at all; the 180 numbers itself 8 when the
    previous reliable response was 3; and the PRACK acknowledges it with the
    PRACK's own CSeq rather than the response's.
    """
    b = Builder()
    cid = "rel100-1@example.net"
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=sdp(CALLER, CALLER_MEDIA),
                                      extra="Supported: 100rel\n"))
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag=""))
    # Reliable, numbered 3, and correctly PRACKed - the control case.
    b.sip(0.20, CALLEE, CALLER, response(183, "Session Progress", cid,
                                         extra="Require: 100rel\nRSeq: 3\n"))
    b.sip(0.25, CALLER, CALLEE, request("PRACK", cid, cseq=2, branch="z9hG4bK-pra-1",
                                        extra="RAck: 3 1 INVITE\n"))
    b.sip(0.28, CALLEE, CALLER, response(200, "OK", cid, cseq=2, method="PRACK",
                                         branch="z9hG4bK-pra-1"))
    # Reliable, but the sequence jumps, and the PRACK cites the wrong CSeq.
    b.sip(0.50, CALLEE, CALLER, response(180, "Ringing", cid,
                                         extra="Require: 100rel\nRSeq: 8\n"))
    b.sip(0.55, CALLER, CALLEE, request("PRACK", cid, cseq=3, branch="z9hG4bK-pra-2",
                                        extra="RAck: 8 3 INVITE\n"))
    b.sip(0.58, CALLEE, CALLER, response(481, "Call/Transaction Does Not Exist", cid,
                                         cseq=3, method="PRACK", branch="z9hG4bK-pra-2"))
    # Reliable in name only: no RSeq, so it can never be acknowledged.
    b.sip(1.00, CALLEE, CALLER, response(183, "Session Progress", cid,
                                         extra="Require: 100rel\n"))
    b.sip(2.00, CALLEE, CALLER, response(200, "OK", cid, body=sdp(CALLEE, CALLEE_MEDIA),
                                         contact=f"<sip:bob@{CALLEE}>"))
    b.sip(2.05, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1"))
    b.rtp(2.10, CALLER, CALLEE, CALLER_MEDIA, CALLEE_MEDIA, ssrc=0xAAAA, count=200)
    b.rtp(2.10, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=200)
    b.sip(7.0, CALLER, CALLEE, request("BYE", cid, cseq=4, branch="z9hG4bK-bye-1"))
    b.sip(7.05, CALLEE, CALLER, response(200, "OK", cid, cseq=4, method="BYE",
                                         branch="z9hG4bK-bye-1"))
    # The 481 answering the unmatched PRACK is a real in-dialog 481 as well; the
    # two findings together are exactly the symptom pair the catalog describes.
    return b.write(path), {"SIP-RSEQ-MISSING", "SIP-RACK-MISMATCH",
                           "SIP-RSEQ-NOT-SEQUENTIAL", "SIP-PRACK-MISSING",
                           "SIP-IN-DIALOG-481"}


def proxied_call(path: pathlib.Path = DATA / "proxied.pcap") -> tuple[pathlib.Path, set[str]]:
    """A clean call through a proxy, captured on both sides of it.

    Every request appears twice with the same From tag and CSeq but a different
    branch, and the second copy carries the proxy's Via on top of the first's
    (RFC 3261 section 16.6). That is an ordinary hop, not a forked request
    merging at the UAS and not a CSeq reuse.
    """
    b = Builder()
    cid = "proxied-1@example.net"
    offer, answer = sdp(CALLER, CALLER_MEDIA), sdp(CALLEE, CALLEE_MEDIA)
    rr = f"<sip:{PROXY};lr>"
    via_uac = "Via: SIP/2.0/UDP 203.0.113.10:5060;branch=z9hG4bK-inv-1;rport\n"
    via_ack = "Via: SIP/2.0/UDP 203.0.113.10:5060;branch=z9hG4bK-ack-1;rport\n"
    via_bye = "Via: SIP/2.0/UDP 203.0.113.10:5060;branch=z9hG4bK-bye-1;rport\n"

    # The forwarded copy: the proxy's Via on top, the original below it. The
    # helpers emit one Via, so the inherited stack rides along in `extra`.
    b.sip(0.00, CALLER, PROXY, invite(cid, body=offer))
    b.sip(0.01, PROXY, CALLEE, invite(cid, body=offer, via_host=PROXY,
                                      branch="z9hG4bK-inv-p1", max_forwards=69,
                                      extra=via_uac))
    b.sip(0.02, PROXY, CALLER, response(100, "Trying", cid, ttag=""))
    b.sip(0.20, CALLEE, PROXY, response(180, "Ringing", cid, via_host=PROXY,
                                        branch="z9hG4bK-inv-p1", record_route=rr,
                                        extra=via_uac))
    b.sip(0.21, PROXY, CALLER, response(180, "Ringing", cid, record_route=rr))
    b.sip(1.00, CALLEE, PROXY, response(200, "OK", cid, body=answer, via_host=PROXY,
                                        branch="z9hG4bK-inv-p1", record_route=rr,
                                        contact=f"<sip:bob@{CALLEE}>", extra=via_uac))
    b.sip(1.01, PROXY, CALLER, response(200, "OK", cid, body=answer, record_route=rr,
                                        contact=f"<sip:bob@{CALLEE}>"))
    b.sip(1.05, CALLER, PROXY, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1",
                                       route=rr))
    b.sip(1.06, PROXY, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-p1",
                                       via_host=PROXY, extra=via_ack))
    b.rtp(1.10, CALLER, CALLEE, CALLER_MEDIA, CALLEE_MEDIA, ssrc=0xAAAA, count=250)
    b.rtp(1.10, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=250)
    b.sip(6.00, CALLER, PROXY, request("BYE", cid, cseq=2, branch="z9hG4bK-bye-1",
                                       route=rr))
    b.sip(6.01, PROXY, CALLEE, request("BYE", cid, cseq=2, branch="z9hG4bK-bye-p1",
                                       via_host=PROXY, extra=via_bye))
    b.sip(6.05, CALLEE, PROXY, response(200, "OK", cid, cseq=2, method="BYE",
                                        via_host=PROXY, branch="z9hG4bK-bye-p1",
                                        extra=via_bye))
    b.sip(6.06, PROXY, CALLER, response(200, "OK", cid, cseq=2, method="BYE",
                                        branch="z9hG4bK-bye-1"))
    return b.write(path), set()


def silence_suppression(path: pathlib.Path = DATA / "silence.pcap"
                        ) -> tuple[pathlib.Path, set[str]]:
    """A call where one side goes quiet and resumes with the marker bit set.

    The RTP timestamp legitimately skips the silence (RFC 3550 section 5.1), so
    the jump must not be reported as a broken clock.
    """
    b = Builder()
    cid = "silence-1@example.net"
    offer, answer = sdp(CALLER, CALLER_MEDIA), sdp(CALLEE, CALLEE_MEDIA)
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=offer))
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag=""))
    b.sip(1.00, CALLEE, CALLER, response(200, "OK", cid, body=answer,
                                         contact=f"<sip:bob@{CALLEE}>"))
    b.sip(1.05, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1"))
    b.rtp(1.10, CALLER, CALLEE, CALLER_MEDIA, CALLEE_MEDIA, ssrc=0xAAAA, count=250,
          pause=(120, 2.0))
    b.rtp(1.10, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=250)
    b.sip(9.00, CALLER, CALLEE, request("BYE", cid, cseq=2, branch="z9hG4bK-bye-1"))
    b.sip(9.05, CALLEE, CALLER, response(200, "OK", cid, cseq=2, method="BYE",
                                         branch="z9hG4bK-bye-1"))
    return b.write(path), set()


def busy_trunk(path: pathlib.Path = DATA / "busytrunk.pcap"
               ) -> tuple[pathlib.Path, set[str]]:
    """One call amid the traffic a real trunk capture is actually made of.

    Grouping by Call-ID counts six here; a VoIP analyser counts one. The mix —
    OPTIONS keepalives, a REGISTER, a NOTIFY and a BYE for a call that was
    already up — is what makes the two numbers disagree.
    """
    b = Builder()
    cid = "trunk-call-1@example.net"
    offer, answer = sdp(CALLER, CALLER_MEDIA), sdp(CALLEE, CALLEE_MEDIA)
    b.sip(0.0, CALLER, CALLEE, invite(cid, body=offer))
    b.sip(0.05, CALLEE, CALLER, response(100, "Trying", cid, ttag=""))
    b.sip(1.00, CALLEE, CALLER, response(200, "OK", cid, body=answer,
                                         contact=f"<sip:bob@{CALLEE}>"))
    b.sip(1.05, CALLER, CALLEE, request("ACK", cid, cseq=1, branch="z9hG4bK-ack-1"))
    b.rtp(1.10, CALLER, CALLEE, CALLER_MEDIA, CALLEE_MEDIA, ssrc=0xAAAA, count=200)
    b.rtp(1.10, CALLEE, CALLER, CALLEE_MEDIA, CALLER_MEDIA, ssrc=0xBBBB, count=200)
    b.sip(5.20, CALLER, CALLEE, request("BYE", cid, cseq=2, branch="z9hG4bK-bye-1"))
    b.sip(5.25, CALLEE, CALLER, response(200, "OK", cid, cseq=2, method="BYE",
                                         branch="z9hG4bK-bye-1"))

    for i, t in enumerate((0.5, 2.5, 4.5)):
        ping = f"ping-{i}@example.net"
        b.sip(t, CALLEE, CALLER, request("OPTIONS", ping, cseq=1, ttag="",
                                         branch=f"z9hG4bK-opt-{i}",
                                         caller=CALLEE, callee=CALLER,
                                         target=f"sip:{CALLER}"))
        b.sip(t + 0.01, CALLER, CALLEE,
              response(200, "OK", ping, cseq=1, method="OPTIONS", ttag="opt",
                       caller=CALLEE, callee=CALLER, branch=f"z9hG4bK-opt-{i}"))

    reg = "trunk-reg-1@example.net"
    b.sip(3.0, CALLER, CALLEE, request("REGISTER", reg, cseq=1, ttag="",
                                       branch="z9hG4bK-reg-9", target=f"sip:{CALLEE}",
                                       contact=f"<sip:alice@{CALLER}>",
                                       extra="Expires: 600\n"))
    b.sip(3.05, CALLEE, CALLER, response(200, "OK", reg, cseq=1, method="REGISTER",
                                         ttag="reg", branch="z9hG4bK-reg-9",
                                         contact=f"<sip:alice@{CALLER}>;expires=600"))

    note = "trunk-notify-1@example.net"
    b.sip(3.5, CALLEE, CALLER, request("NOTIFY", note, cseq=1,
                                       branch="z9hG4bK-not-1", caller=CALLEE,
                                       callee=CALLER, target=f"sip:{CALLER}",
                                       extra="Event: keep-alive\nSubscription-State: active\n"))
    b.sip(3.55, CALLER, CALLEE, response(200, "OK", note, cseq=1, method="NOTIFY",
                                         caller=CALLEE, callee=CALLER,
                                         branch="z9hG4bK-not-1"))

    # A call that was already up when the capture started: only its teardown is here.
    old = "trunk-old-1@example.net"
    b.sip(6.0, CALLER, CALLEE, request("BYE", old, cseq=17, branch="z9hG4bK-bye-old"))
    b.sip(6.05, CALLEE, CALLER, response(200, "OK", old, cseq=17, method="BYE",
                                         branch="z9hG4bK-bye-old"))
    return b.write(path), set()


def two_capture_points(path: pathlib.Path = DATA / "twopoints.txt"
                       ) -> tuple[pathlib.Path, set[str]]:
    """tcpdump -v output holding the same REGISTER exchange either side of a NAT.

    Modelled on a real trace: SIP indented 8 spaces under the IP line, endpoints
    written as 10.1.0.150.5060 > 10.0.0.21.50210, and every packet present twice
    with a rewritten address but the same IPv4 id. Without capture-point detection
    this reads as a doubled auth challenge and a 0 ms "retransmission".
    """
    inside, outside, ua = "10.1.0.150", "10.2.0.150", "10.0.0.21"
    cid = "twopoints-1@example.net"

    def block(clock: str, ip_id: int, ttl: int, src: str, sport: int,
              dst: str, dport: int, msg: str) -> str:
        head = (f"{clock} IP (tos 0x10, ttl {ttl}, id {ip_id}, offset 0, flags [DF], "
                f"proto UDP (17), length {len(msg) + 28})\n"
                f"    {src}.{sport} > {dst}.{dport}: [udp sum ok] SIP, length: {len(msg)}\n")
        return head + "".join(f"        {line}\n" for line in msg.split("\n"))

    reg = request("REGISTER", cid, cseq=1, ttag="", branch="z9hG4bK-reg-1",
                  caller=ua, callee=inside, target=f"sip:{inside}", via_host=ua)
    chal = response(401, "Unauthorized", cid, cseq=1, method="REGISTER", ttag="srv",
                    caller=ua, callee=inside, branch="z9hG4bK-reg-1", via_host=ua,
                    extra='WWW-Authenticate: Digest realm="example.net", nonce="n1"\n')

    text = "COTE UA (AVANT NAT) :\n\n"
    # Same datagram, same IPv4 id, recorded on both interfaces of the NAT.
    text += block("18:37:08.604582", 885, 64, ua, 50210, inside, 5060, reg)
    text += block("18:37:08.604582", 885, 63, ua, 50210, outside, 5060, reg)
    text += block("18:37:08.691000", 900, 64, inside, 5060, ua, 50210, chal)
    text += block("18:37:08.691000", 900, 63, outside, 5060, ua, 50210, chal)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path, {"CAP-MULTIPLE-CAPTURE-POINTS"}


# ---------------------------------------------------------------- OCOM HTML export
# Addresses for the two-leg B2BUA the export scenarios describe. The SBC answers
# on one address per side, which is the fact a capture cannot know and the export
# states — and the reason these fixtures exist.
SBC_OUT, SBC_IN = "203.0.113.200", "198.51.100.200"
UAC_DEV, SBC_DEV, UAS_DEV = 10, 20, 30
OCOM_DEVICES = [
    ocom_device(UAC_DEV, "uac-gw", [CALLER], "GW"),
    ocom_device(SBC_DEV, "sbc-edge", [SBC_OUT, SBC_IN], "SBC"),
    ocom_device(UAS_DEV, "carrier-trunk", [CALLEE], "TRUNK"),
]
OUT_MEDIA, IN_MEDIA = 41000, 41002


def _ocom_call(*, jitter: float = 0.5, loss_pct: float = 0.0, lost: int = 0,
               mos: float | None = None) -> list[dict]:
    """Two legs of one call across a B2BUA, plus the probe's view of its media.

    Both legs carry the same Call-ID and the same tags — an SBC that keeps the
    dialog identifiers, which is the ordinary case and the one that used to read
    as CSeq reuse and a cross-leg offer/answer pair. Each leg has its own Via and
    its own media address, as a B2BUA anchoring media does.
    """
    cid = "ocom-1@example.net"
    t = lambda ms: f"2026-08-05T15:06:{14 + ms // 1000:02d}.{ms % 1000:03d}000+00:00"  # noqa: E731

    leg0 = {"caller": CALLER, "callee": SBC_OUT, "via_host": None}
    out_offer = sdp(CALLER, CALLER_MEDIA, codecs="8 101")
    out_answer = sdp(SBC_OUT, OUT_MEDIA, codecs="8 101")
    in_offer = sdp(SBC_IN, IN_MEDIA, codecs="8 101")
    in_answer = sdp(CALLEE, CALLEE_MEDIA, codecs="8 101")

    rows = [
        # --- leg 0: the access side
        ocom_sip(t(0), CALLER, SBC_OUT, invite(cid, body=out_offer, **leg0,
                                               branch="z9hG4bK-out-1"),
                 leg=0, src_device=UAC_DEV, dst_device=SBC_DEV, realm="Access"),
        ocom_sip(t(20), SBC_OUT, CALLER, response(100, "Trying", cid, ttag="", **leg0,
                                                  branch="z9hG4bK-out-1"),
                 leg=0, src_device=SBC_DEV, dst_device=UAC_DEV),
        # --- leg 1: the trunk side, same Call-ID and tags, fresh Via
        ocom_sip(t(30), SBC_IN, CALLEE, invite(cid, body=in_offer, caller=CALLER,
                                               callee=CALLEE, via_host=SBC_IN,
                                               branch="z9hG4bK-in-1"),
                 leg=1, src_device=SBC_DEV, dst_device=UAS_DEV, vlan=200),
        ocom_sip(t(50), CALLEE, SBC_IN, response(100, "Trying", cid, ttag="",
                                                 via_host=SBC_IN, branch="z9hG4bK-in-1"),
                 leg=1, src_device=UAS_DEV, dst_device=SBC_DEV, vlan=200),
        ocom_sip(t(900), CALLEE, SBC_IN,
                 response(200, "OK", cid, body=in_answer, via_host=SBC_IN,
                          branch="z9hG4bK-in-1", contact=f"<sip:bob@{CALLEE}>"),
                 leg=1, src_device=UAS_DEV, dst_device=SBC_DEV, vlan=200),
        ocom_sip(t(910), SBC_IN, CALLEE,
                 request("ACK", cid, cseq=1, via_host=SBC_IN, branch="z9hG4bK-in-ack"),
                 leg=1, src_device=SBC_DEV, dst_device=UAS_DEV, vlan=200),
        ocom_sip(t(920), SBC_OUT, CALLER,
                 response(200, "OK", cid, body=out_answer, **leg0,
                          branch="z9hG4bK-out-1", contact=f"<sip:b2b@{SBC_OUT}>"),
                 leg=0, src_device=SBC_DEV, dst_device=UAC_DEV),
        ocom_sip(t(930), CALLER, SBC_OUT,
                 request("ACK", cid, cseq=1, callee=SBC_OUT, branch="z9hG4bK-out-ack"),
                 leg=0, src_device=UAC_DEV, dst_device=SBC_DEV, realm="Access"),
        # --- media, as the probe measured it rather than as packets
        ocom_media(t(1000), CALLER, CALLER_MEDIA, SBC_OUT, OUT_MEDIA, leg=0,
                   src_device=UAC_DEV, dst_device=SBC_DEV),
        ocom_media(t(1000), SBC_IN, IN_MEDIA, CALLEE, CALLEE_MEDIA, leg=1,
                   src_device=SBC_DEV, dst_device=UAS_DEV,
                   jitter=jitter, loss_pct=loss_pct, lost=lost, mos=mos),
        # --- teardown, both legs
        ocom_sip(t(5000), CALLER, SBC_OUT,
                 request("BYE", cid, cseq=2, callee=SBC_OUT, branch="z9hG4bK-out-bye"),
                 leg=0, src_device=UAC_DEV, dst_device=SBC_DEV, realm="Access"),
        ocom_sip(t(5010), SBC_IN, CALLEE,
                 request("BYE", cid, cseq=2, via_host=SBC_IN, branch="z9hG4bK-in-bye"),
                 leg=1, src_device=SBC_DEV, dst_device=UAS_DEV, vlan=200),
        ocom_sip(t(5030), CALLEE, SBC_IN,
                 response(200, "OK", cid, cseq=2, method="BYE", via_host=SBC_IN,
                          branch="z9hG4bK-in-bye"),
                 leg=1, src_device=UAS_DEV, dst_device=SBC_DEV, vlan=200),
        ocom_sip(t(5040), SBC_OUT, CALLER,
                 response(200, "OK", cid, cseq=2, method="BYE", **leg0,
                          branch="z9hG4bK-out-bye"),
                 leg=0, src_device=SBC_DEV, dst_device=UAC_DEV),
        ocom_media(t(5100), CALLER, CALLER_MEDIA, SBC_OUT, OUT_MEDIA, leg=0,
                   src_device=UAC_DEV, dst_device=SBC_DEV, label="END RTP"),
        ocom_media(t(5100), SBC_IN, IN_MEDIA, CALLEE, CALLEE_MEDIA, leg=1,
                   src_device=SBC_DEV, dst_device=UAS_DEV, label="END RTP",
                   jitter=jitter, loss_pct=loss_pct, lost=lost, mos=mos),
    ]
    return rows


def ocom_export(path: pathlib.Path = DATA / "ocom-clean.html"
                ) -> tuple[pathlib.Path, set[str]]:
    """A healthy call across a B2BUA, exported from OCOM. Nothing to report.

    This is the fixture that pins the correlated-trace behaviour: one Call-ID,
    one pair of tags, two legs. Every pairwise check in the dialog has to scope
    itself to a leg or it fires on the second hop of a call that is fine.
    """
    return write_ocom(path, _ocom_call(), OCOM_DEVICES), set()


def ocom_bad_media(path: pathlib.Path = DATA / "ocom-media.html"
                   ) -> tuple[pathlib.Path, set[str]]:
    """The same call, with the probe reporting a trunk leg nobody would enjoy."""
    entries = _ocom_call(jitter=48.0, loss_pct=3.2, lost=8, mos=2.9)
    return (write_ocom(path, entries, OCOM_DEVICES),
            {"MEDIA-REPORTED-LOSS", "MEDIA-REPORTED-JITTER", "MEDIA-REPORTED-MOS-LOW"})


def ocom_varied_topologies(path: pathlib.Path = DATA / "ocom-varied.html"
                           ) -> tuple[pathlib.Path, set[str]]:
    """One export, three calls, no two the same shape.

    A direct call over one leg between two devices; the two-leg B2BUA call above;
    and a four-leg call across five. Nothing in the reader, the model or the UI
    may hold a leg count or a device count still: they are properties of each
    call, and an export routinely carries calls that disagree about both.
    """
    hop = ["11.0.0.1", "11.0.0.2", "11.0.0.3", "11.0.0.4", "11.0.0.5"]
    devices = OCOM_DEVICES + [
        ocom_device(40 + i, f"hop{i}", [addr], "SBC") for i, addr in enumerate(hop)
    ]
    t = lambda n, ms: f"2026-08-05T16:{n:02d}:{ms // 1000:02d}.{ms % 1000:03d}000+00:00"  # noqa: E731

    # --- one leg, two devices: a UA straight onto the trunk
    direct = "ocom-direct@example.net"
    rows = [
        ocom_sip(t(10, 0), CALLER, CALLEE, invite(direct, body=sdp(CALLER, CALLER_MEDIA,
                                                                   codecs="8 101")),
                 leg=0, src_device=UAC_DEV, dst_device=UAS_DEV),
        ocom_sip(t(10, 900), CALLEE, CALLER,
                 response(200, "OK", direct, body=sdp(CALLEE, CALLEE_MEDIA, codecs="8 101"),
                          contact=f"<sip:bob@{CALLEE}>"),
                 leg=0, src_device=UAS_DEV, dst_device=UAC_DEV),
        ocom_sip(t(10, 950), CALLER, CALLEE, request("ACK", direct, cseq=1,
                                                     branch="z9hG4bK-d-ack"),
                 leg=0, src_device=UAC_DEV, dst_device=UAS_DEV),
        ocom_sip(t(20, 0), CALLER, CALLEE, request("BYE", direct, cseq=2,
                                                   branch="z9hG4bK-d-bye"),
                 leg=0, src_device=UAC_DEV, dst_device=UAS_DEV),
        ocom_sip(t(20, 50), CALLEE, CALLER,
                 response(200, "OK", direct, cseq=2, method="BYE", branch="z9hG4bK-d-bye"),
                 leg=0, src_device=UAS_DEV, dst_device=UAC_DEV),
    ]

    # --- the two-leg B2BUA call, unchanged
    rows += _ocom_call()

    # --- four legs across five devices, leg numbers deliberately not starting at 0
    chained = "ocom-chain@example.net"
    for leg, (a, b) in enumerate(zip(hop, hop[1:], strict=False), start=7):
        ms = leg * 10
        rows += [
            ocom_sip(t(30, ms), a, b,
                     invite(chained, body=sdp(a, CALLER_MEDIA, codecs="8 101"),
                            caller=CALLER, callee=CALLEE, via_host=a,
                            branch=f"z9hG4bK-c{leg}"),
                     leg=leg, src_device=40 + leg - 7, dst_device=41 + leg - 7),
            ocom_sip(t(30, 900 + ms), b, a,
                     response(200, "OK", chained, body=sdp(b, CALLEE_MEDIA, codecs="8 101"),
                              via_host=a, branch=f"z9hG4bK-c{leg}",
                              contact=f"<sip:bob@{b}>"),
                     leg=leg, src_device=41 + leg - 7, dst_device=40 + leg - 7),
            ocom_sip(t(31, ms), a, b,
                     request("ACK", chained, cseq=1, via_host=a,
                             branch=f"z9hG4bK-c{leg}-ack", target=f"sip:bob@{b}"),
                     leg=leg, src_device=40 + leg - 7, dst_device=41 + leg - 7),
            ocom_sip(t(40, ms), a, b,
                     request("BYE", chained, cseq=2, via_host=a,
                             branch=f"z9hG4bK-c{leg}-bye", target=f"sip:bob@{b}"),
                     leg=leg, src_device=40 + leg - 7, dst_device=41 + leg - 7),
            ocom_sip(t(40, 50 + ms), b, a,
                     response(200, "OK", chained, cseq=2, method="BYE", via_host=a,
                              branch=f"z9hG4bK-c{leg}-bye"),
                     leg=leg, src_device=41 + leg - 7, dst_device=40 + leg - 7),
        ]
    return write_ocom(path, rows, devices), set()


ALL = [clean_call, missing_ack, nat_private, codec_mismatch, auth_loop, invite_timeout,
       packet_loss, direction_mismatch, session_timer, text_log, nat_registration,
       mirrored_capture, two_capture_points, busy_trunk, proxied_call,
       silence_suppression, answer_without_contact, reinvite_before_answer,
       update_refused, require_rejected, redirect_ignored, early_media_on_180,
       rel100_broken, ocom_export, ocom_bad_media, ocom_varied_topologies]

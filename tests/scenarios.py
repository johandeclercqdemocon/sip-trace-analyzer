"""Synthetic traces. Each returns (path, expected_check_ids)."""
from __future__ import annotations

import pathlib

from .builder import CALLEE, CALLER, Builder, invite, request, response, sdp

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


ALL = [clean_call, missing_ack, nat_private, codec_mismatch, auth_loop, invite_timeout,
       packet_loss, direction_mismatch, session_timer, text_log, nat_registration,
       mirrored_capture, two_capture_points]

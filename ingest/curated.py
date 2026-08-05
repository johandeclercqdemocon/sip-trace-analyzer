"""Curated diagnostic knowledge: what a response code means in a real trace, and
the catalog of failure modes the bot looks for.

Every rfc_refs entry is 'RFC#SECTION' and is validated against rfc_section at load
time, so a citation that does not exist fails the build rather than reaching a report.
"""
from __future__ import annotations

# ---------------------------------------------------------------- response codes
# code: (meaning, likely_causes, next_checks, who_emits, severity, terminates_dialog)
RESPONSE_DIAGNOSTICS: dict[int, tuple] = {
    100: ("Hop-by-hop acknowledgement that the request was received. Never forwarded end to end. "
          "Its absence within ~200 ms on UDP is itself a finding, because the UAC will start retransmitting.",
          ["normal"], ["If missing, check for INVITE retransmissions at 500 ms/1 s/2 s intervals"],
          "either", "info", False),
    180: ("The far end is alerting. No media is guaranteed; audio before 200 OK requires 183 with SDP or early media.",
          ["normal"], ["If the caller hears silence, look for 180 without SDP where the UA expected early media"],
          "uas", "info", False),
    181: ("The call is being forwarded. Diversion/History-Info should say where.",
          ["call forwarding configured"], ["Check History-Info or Diversion for the forwarding chain"],
          "either", "info", False),
    182: ("Queued at the far end (e.g. call centre). Long 182 phases end in Timer C expiry at the proxy.",
          ["queueing"], ["Check elapsed time against proxy Timer C (> 3 min)"], "uas", "info", False),
    183: ("Session progress, normally carrying early-media SDP. If SDP is present, RTP should start flowing "
          "immediately and one-way audio complaints usually start here.",
          ["early media from a gateway", "ringback from the PSTN"],
          ["Confirm SDP is present", "Confirm RTP actually arrives from the 183 SDP address"],
          "either", "info", False),
    199: ("One early dialog of a forked INVITE has been terminated; other branches continue.",
          ["forking"], ["Correlate remaining early dialogs by to-tag"], "either", "info", False),
    200: ("Success. For INVITE it must be ACKed end to end; unACKed 200s are retransmitted until Timer H.",
          ["normal"], ["For INVITE, verify a matching ACK within 200 ms and no 200 retransmissions"],
          "either", "info", False),
    202: ("Accepted. Deprecated for SUBSCRIBE/REFER by RFC 6665 - modern stacks send 200.",
          ["legacy stack"], ["Treat as success but note the peer predates RFC 6665"], "uas", "info", False),
    300: ("Multiple choices. The UAC must pick a Contact and retry.",
          ["redirect server"], ["Check whether the UAC actually retried any Contact"], "either", "info", False),
    301: ("The address of record has moved permanently. Registration/provisioning data is stale.",
          ["moved AoR"], ["Update the dial plan; a UA that ignores this will keep failing"], "either", "warning", False),
    302: ("Moved temporarily - the workhorse redirect. Contact carries the new target; a redirect loop here "
          "is a classic cause of 'call rings forever'.",
          ["call forwarding", "redirect server", "load distribution"],
          ["Follow the Contact and check for a loop back to the original target",
           "Check that the UAC honours the Contact's expires/q values"],
          "either", "info", False),
    305: ("Use the proxy in Contact. Rare; usually a policy device.", ["policy routing"],
          ["Confirm the UAC supports it - many ignore 305"], "proxy", "warning", False),
    380: ("Alternative service, e.g. 'try voicemail'. Body may describe the alternative.",
          ["service substitution"], ["Check for an accompanying body"], "either", "info", False),
    400: ("The receiver could not parse the request. Almost always a malformed header on the sending side.",
          ["malformed header", "illegal characters", "bad URI escaping", "missing mandatory header"],
          ["Read the reason phrase - it usually names the offending header",
           "Diff the request against the mandatory-header set for its method"],
          "either", "error", False),
    401: ("The UAS or registrar wants digest authentication. Expected once per REGISTER/INVITE; "
          "seeing it repeatedly means the credentials or the digest computation are wrong.",
          ["first leg of normal digest auth", "wrong password", "wrong realm", "algorithm mismatch (MD5 vs SHA-256)"],
          ["Count 401s per Call-ID - more than one round is a failure",
           "Check the retry increments CSeq and echoes realm/nonce/opaque exactly"],
          "uas", "info", False),
    402: ("Reserved by RFC 3261; in the wild it is used by some carriers for billing/credit refusal.",
          ["prepaid balance", "non-standard carrier use"], ["Ask the carrier - this is not standardised"],
          "either", "error", False),
    403: ("Understood and refused; retrying will not help. In carrier traces this is the standard "
          "'you are not allowed to send this' answer.",
          ["caller ID not permitted", "source IP not in the ACL", "unauthorised prefix or destination",
           "trunk not provisioned", "toll fraud protection"],
          ["Compare the From/P-Asserted-Identity against what the trunk expects",
           "Check the source IP against the peer's ACL", "Read the reason phrase - carriers put the real cause there"],
          "either", "error", False),
    404: ("The server has definitive knowledge that the user does not exist at that domain - "
          "or the domain in the Request-URI is not one it serves.",
          ["wrong number", "wrong domain in Request-URI", "number not provisioned", "dial plan gap"],
          ["Check the Request-URI domain against the peer's served domains",
           "Check number normalisation (E.164 vs national format)"],
          "either", "error", False),
    405: ("The method is not allowed for that target. The Allow header in the response lists what is.",
          ["UA does not support the method (e.g. UPDATE, INFO, REFER)"],
          ["Read the Allow header and stop sending the method"], "uas", "error", False),
    407: ("Same as 401 but from a proxy. Credentials go in Proxy-Authorization, not Authorization - "
          "sending the wrong one is a common cause of auth loops.",
          ["normal proxy auth", "credentials placed in the wrong header", "wrong realm"],
          ["Verify the retry uses Proxy-Authorization", "Count rounds - more than one is a failure"],
          "proxy", "info", False),
    408: ("No timely answer. Generated by a server, or synthesised locally when Timer B/F expires "
          "after 64*T1 (32 s by default) of retransmissions.",
          ["far end unreachable", "packet loss", "firewall dropping the request", "downstream server hung"],
          ["Look for the retransmission ladder at 0.5/1/2/4/4... s before the 408",
           "Confirm whether the 408 came on the wire or was generated locally"],
          "either", "error", True),
    410: ("Gone - permanent, and the server knows it. Stronger statement than 404.",
          ["number decommissioned"], ["Remove from the dial plan"], "either", "error", False),
    412: ("Conditional request failed - the SIP-If-Match entity tag is stale (PUBLISH).",
          ["expired publication"], ["Re-PUBLISH without SIP-If-Match"], "uas", "warning", False),
    413: ("Request body too large for the server to process.",
          ["huge SDP", "large multipart body"], ["Check message size; consider TCP"], "either", "error", False),
    414: ("Request-URI too long.", ["runaway URI parameters"], ["Inspect the Request-URI length"],
          "either", "error", False),
    415: ("The body's content type is not supported. Accept in the response lists what is.",
          ["multipart body sent to a UA that wants application/sdp only", "ISUP body on a non-SIP-I peer"],
          ["Read the Accept header of the response", "Strip the unsupported body part"],
          "uas", "error", False),
    416: ("Unsupported URI scheme, e.g. a sips: URI sent to a UA that only does sip:, or tel: to a UA that wants sip:.",
          ["sips: not supported", "tel: URI not supported"], ["Rewrite the Request-URI scheme"],
          "either", "error", False),
    420: ("An extension listed in Require or Proxy-Require is not supported. The Unsupported header "
          "of the response names it.",
          ["Require: 100rel against a UA without PRACK", "Require: timer", "Require: precondition"],
          ["Read Unsupported in the response", "Move the tag from Require to Supported if it is optional"],
          "either", "error", False),
    421: ("The UAS needs an extension the UAC did not offer; Require in the response names it.",
          ["server demands an extension"], ["Add the named tag to Supported and retry"], "uas", "error", False),
    422: ("Session-Expires is smaller than the peer's Min-SE. The UAC must retry with at least that Min-SE. "
          "A repeated 422 for the same Call-ID is a configuration loop.",
          ["Session-Expires below the peer's minimum", "UAC ignores Min-SE in the 422"],
          ["Read Min-SE from the 422 and confirm the retry uses >= that value",
           "Count 422s per Call-ID"], "either", "error", False),
    423: ("The registration expiry is shorter than the registrar's minimum; Min-Expires says the floor.",
          ["client refresh interval too short"], ["Retry with expires >= Min-Expires"], "registrar", "warning", False),
    428: ("An Identity header (STIR/SHAKEN) is required and was absent.",
          ["missing attestation"], ["Check the signing path"], "either", "error", False),
    430: ("The flow to that registered contact is dead (RFC 5626 outbound).",
          ["NAT binding lost", "TCP connection closed"], ["Check keepalive interval against the NAT timeout"],
          "proxy", "error", False),
    433: ("Anonymous calling is disallowed by policy.", ["Privacy: id with an anonymous From"],
          ["Check the Privacy header and the peer's anonymous-call policy"], "either", "error", False),
    436: ("Identity-Info could not be dereferenced (STIR/SHAKEN).", ["certificate fetch failed"],
          ["Check certificate repository reachability"], "either", "error", False),
    438: ("The Identity header failed validation (STIR/SHAKEN).", ["signature mismatch", "clock skew"],
          ["Check signing certificate and the iat claim against wall clock"], "either", "error", False),
    439: ("The first hop does not support outbound, so the registration cannot use flow tokens.",
          ["edge proxy lacks RFC 5626 support"], ["Disable outbound on the client or upgrade the edge proxy"],
          "registrar", "warning", False),
    469: ("The Info-Package in an INFO request is not supported.", ["INFO package mismatch"],
          ["Read Recv-Info in the response"], "uas", "warning", False),
    480: ("The far end was reached but is not available - not logged in, DND, or no valid forwarding "
          "location. Distinct from 486: nothing is ringing.",
          ["callee not registered", "do not disturb", "no valid binding at the registrar",
           "carrier-side 'subscriber unavailable'"],
          ["Check whether the callee has a live registration",
           "Read the reason phrase - it usually carries the specific cause",
           "Check Retry-After for a suggested retry time"],
          "either", "error", False),
    481: ("The receiver has no matching dialog or transaction. Sent in response to an in-dialog request "
          "that the peer no longer recognises - the single most useful signal that dialog state has diverged.",
          ["BYE/re-INVITE after the peer already tore the dialog down",
           "wrong To/From tag on the in-dialog request", "dialog lost on a restarted or failed-over server",
           "Route set wrong so the request reached the wrong element",
           "REFER with Replaces pointing at a dead dialog"],
          ["Compare Call-ID plus both tags against the dialog-establishing 200 OK",
           "Check the Route set against the Record-Route from the 200 OK",
           "Look for an earlier BYE from the other side"],
          "either", "error", True),
    482: ("The server saw its own Via in the request (a loop) or detected merged branches.",
          ["routing loop between two proxies", "misconfigured redirect pointing back",
           "forked request merging at a UAS"],
          ["Count Via headers and find the repeated host",
           "Check for a 302 that points back into the same proxy"],
          "proxy", "error", False),
    483: ("Max-Forwards reached zero. Almost always a loop that 482 detection did not catch.",
          ["routing loop", "Max-Forwards set too low at the origin (default should be 70)"],
          ["Check the initial Max-Forwards value", "Trace the hop chain via the Via stack"],
          "proxy", "error", False),
    484: ("Request-URI incomplete - overlap dialling. Expected in ISDN-style overlap setups; "
          "unexpected elsewhere it means the digits were truncated.",
          ["overlap dialling", "truncated dialled number"], ["Check the digit string length"],
          "either", "error", False),
    485: ("The Request-URI matched more than one user.", ["ambiguous alias"],
          ["Read the Contact list in the response"], "either", "error", False),
    486: ("The callee's device was reached and is busy. Distinct from 480: the endpoint answered the signalling.",
          ["all lines in use", "user pressed reject", "call-waiting disabled",
           "carrier returning busy for a congested trunk"],
          ["Check whether the callee has other active dialogs at that time",
           "Distinguish device-busy from network-busy via the emitting element"],
          "uas", "info", False),
    487: ("The request was terminated, normally because a CANCEL arrived. It must be preceded by a CANCEL "
          "(or a BYE that killed the pending branch) and followed by an ACK.",
          ["caller hung up before answer", "forking: losing branch cancelled after another answered",
           "proxy Timer C expiry cancelling a stalled branch"],
          ["Find the matching CANCEL - a 487 without one means the cancel was generated upstream",
           "Verify an ACK follows the 487 (it is a non-2xx final response)"],
          "either", "info", True),
    488: ("Media negotiation failed for this target specifically. The most common SDP-level failure.",
          ["no codec in common", "RTP/SAVP offered to a non-SRTP peer (or the reverse)",
           "unsupported media type such as video or T.38", "ptime or bandwidth constraint",
           "IPv6 in c= to an IPv4-only peer"],
          ["Diff the offered m=/a=rtpmap set against what the peer supports",
           "Check the transport profile on the m= line (RTP/AVP vs RTP/SAVP vs UDP/TLS/RTP/SAVP)",
           "Look for a warning header or an SDP body in the 488"],
          "uas", "error", False),
    489: ("The Event package in SUBSCRIBE/NOTIFY is not supported.", ["event package mismatch"],
          ["Read Allow-Events in the response"], "uas", "error", False),
    491: ("Both ends sent an in-dialog INVITE at the same time (glare). The RFC prescribes a randomised "
          "backoff based on who owns the Call-ID; a repeated 491 means one side is not backing off.",
          ["simultaneous re-INVITE, typically hold vs codec renegotiation",
           "session-timer refresh colliding with a hold"],
          ["Check whether the retry waited 2.1-4 s (Call-ID owner) or 0-2 s (the other side)",
           "Count 491s per dialog"], "uas", "warning", False),
    493: ("The body was encrypted and the receiver cannot decrypt it.", ["S/MIME key mismatch"],
          ["Check the encryption configuration"], "uas", "error", False),
    494: ("Security agreement (RFC 3329) is required before proceeding.", ["Sec-Agree negotiation"],
          ["Add Security-Client and retry"], "either", "error", False),
    500: ("The server hit an internal error. Opaque by nature - the cause is in that server's own logs.",
          ["software fault", "database unreachable", "script error in the routing logic",
           "malformed message that got past the parser"],
          ["Correlate with the server's logs at that timestamp",
           "Check whether it is reproducible or a one-off"], "either", "error", False),
    501: ("The method is not implemented at all by that server (versus 405, which is per-target).",
          ["method unsupported by the element"], ["Stop sending the method to that element"],
          "either", "error", False),
    502: ("A gateway/proxy got an invalid answer from downstream.",
          ["downstream returned garbage", "DNS resolved to a dead host", "TLS handshake failure downstream"],
          ["Look at what the next hop actually returned", "Check the DNS/SRV resolution for the next hop"],
          "proxy", "error", False),
    503: ("Temporary overload or maintenance. A UAC or proxy receiving this should fail over to another "
          "server and stop sending to this one for the Retry-After period. Frequently a whole-trunk symptom, "
          "not a per-call one.",
          ["trunk in overload", "capacity/CPS limit hit", "element in maintenance",
           "SBC rejecting because a downstream is down", "no route available on the far side"],
          ["Check whether it affects all calls or just this one",
           "Read Retry-After and whether the sender honoured it",
           "Check whether failover to an alternate target happened (RFC 3263)"],
          "either", "error", False),
    504: ("A downstream server did not answer in time. The upstream leg is fine, the failure is beyond it.",
          ["downstream timeout", "DNS resolution timeout", "far end silently dropping"],
          ["Identify the next hop and check its reachability"], "proxy", "error", False),
    505: ("SIP version not supported.", ["non-SIP/2.0 request line"], ["Check the request line"],
          "either", "error", False),
    513: ("Message too large for the transport, typically an oversized UDP datagram.",
          ["large SDP or headers over UDP"], ["Switch to TCP - RFC 3261 requires it above the MTU threshold"],
          "either", "error", False),
    580: ("Preconditions could not be met (RFC 3312, common in IMS).",
          ["QoS precondition failure"], ["Check the a=curr/a=des precondition attributes"],
          "uas", "error", False),
    600: ("Busy everywhere - the callee is busy at every device and no other endpoint should be tried. "
          "Stronger than 486, and it stops forking.",
          ["global busy"], ["Distinguish from 486 - this suppresses further forking"], "uas", "info", False),
    603: ("Declined by the user. Deliberate rejection, not a fault. Carriers also use it for policy blocks.",
          ["user rejected the call", "carrier policy rejection", "anti-fraud block"],
          ["Read the reason phrase - carriers put the real cause there"], "uas", "info", False),
    604: ("The user does not exist anywhere - a global 404, and it stops forking.",
          ["unknown number, authoritative answer"], ["Check the dial plan"], "uas", "error", False),
    606: ("The session description is unacceptable everywhere, not just here.",
          ["global media incompatibility"], ["Compare with 488, which is per-target"], "uas", "error", False),
    607: ("The callee marked the call unwanted (RFC 8197). Robocall feedback.",
          ["user marked as spam"], ["Check the calling number's reputation"], "uas", "info", False),
    608: ("Rejected by an intermediary as unwanted, with a jCard in the body explaining how to appeal.",
          ["analytics engine blocked the call"], ["Read the Call-Info jCard for the appeal contact"],
          "proxy", "warning", False),
}

# ---------------------------------------------------------------- methods
# name: (summary, creates_dialog, within_dialog, target_refresh, invite_txn, ack_required, cancellable)
METHODS: dict[str, tuple] = {
    "INVITE":    ("Establishes a session. The only method using the INVITE transaction state machine, "
                  "the only one requiring an end-to-end ACK, and the only one that can fork into multiple dialogs.",
                  True, True, True, True, True, True),
    "ACK":       ("Acknowledges a final response to INVITE. For 2xx it is a separate end-to-end transaction "
                  "generated by the UAC core; for non-2xx it is hop-by-hop and generated by the transaction layer.",
                  False, True, False, False, False, False),
    "BYE":       ("Terminates an established dialog. Never sent for an early dialog - CANCEL is used there.",
                  False, True, False, False, False, False),
    "CANCEL":    ("Cancels a pending INVITE. Hop-by-hop, and only meaningful before a final response. "
                  "Racing a 200 OK makes it useless - a BYE is then required.",
                  False, False, False, False, False, False),
    "REGISTER":  ("Binds an address of record to one or more contacts at a registrar. Not a dialog.",
                  False, False, False, False, False, False),
    "OPTIONS":   ("Queries capabilities. Widely repurposed as a trunk keepalive/heartbeat, which is why "
                  "traces are full of them.",
                  False, True, False, False, False, False),
    "PRACK":     ("Acknowledges a reliably-sent provisional response (RFC 3262). Missing PRACKs cause "
                  "18x retransmission storms.",
                  False, True, False, False, False, False),
    "UPDATE":    ("Modifies session parameters, including before the call is answered - the correct way to "
                  "renegotiate during early media, where re-INVITE is not allowed.",
                  False, True, True, False, False, False),
    "SUBSCRIBE": ("Requests notification of an event package. Creates its own dialog.",
                  True, True, True, False, False, True),
    "NOTIFY":    ("Delivers event state. Must be sent immediately after an accepted SUBSCRIBE.",
                  False, True, True, False, False, False),
    "REFER":     ("Asks the recipient to contact a third party - the transfer primitive. Progress is reported "
                  "with NOTIFY carrying message/sipfrag.",
                  True, True, True, False, False, True),
    "PUBLISH":   ("Publishes event state to a state agent (RFC 3903).",
                  False, False, False, False, False, False),
    "MESSAGE":   ("Carries an instant message. Normally outside any dialog.",
                  False, True, False, False, False, False),
    "INFO":      ("Carries mid-call application information, classically DTMF for gateways that do not "
                  "support RFC 4733.",
                  False, True, False, False, False, False),
}

# ---------------------------------------------------------------- timers (RFC 3261 Table 4)
# name: (default, seconds, section, meaning, applies_to, transport)
T1, T2, T4 = 0.5, 4.0, 5.0
TIMERS: dict[str, tuple] = {
    "T1": ("500ms default", T1, "17.1.1.1", "Round-trip time estimate. Every other timer is derived from it, "
           "so a trace showing retransmits at 0.5/1/2/4 s is running stock T1.", "any", "any"),
    "T2": ("4s", T2, "17.1.2.2", "Maximum retransmit interval for non-INVITE requests and INVITE responses.",
           "any", "any"),
    "T4": ("5s", T4, "17.1.2.2", "Maximum time a message remains in the network.", "any", "any"),
    "Timer A": ("initially T1", T1, "17.1.1.2", "INVITE request retransmit interval, doubling each time. UDP only.",
                "uac", "udp"),
    "Timer B": ("64*T1", 64 * T1, "17.1.1.2", "INVITE client transaction timeout - 32 s by default. When it fires "
                "the UAC gives up and reports a 408 to its core. The classic 'call fails after 32 seconds'.",
                "uac", "any"),
    "Timer C": ("> 3min", 180.0, "16.6", "Proxy INVITE transaction timeout. A call stuck in 180/183 for over "
                "3 minutes gets cancelled by the proxy, producing a 487 the UAC never asked for.",
                "proxy", "any"),
    "Timer D": ("> 32s for UDP, 0s for TCP", 32.0, "17.1.1.2",
                "How long the INVITE client transaction absorbs retransmitted non-2xx finals.", "uac", "any"),
    "Timer E": ("initially T1, capped at T2", T1, "17.1.2.2",
                "Non-INVITE request retransmit interval. UDP only.", "uac", "udp"),
    "Timer F": ("64*T1", 64 * T1, "17.1.2.2", "Non-INVITE transaction timeout - 32 s. A BYE or OPTIONS that "
                "vanishes fails here.", "uac", "any"),
    "Timer G": ("initially T1, capped at T2", T1, "17.2.1",
                "INVITE response retransmit interval at the UAS. Seeing repeated 200 OKs at 0.5/1/2/4/4 s "
                "means the ACK never arrived.", "uas", "udp"),
    "Timer H": ("64*T1", 64 * T1, "17.2.1", "How long the UAS waits for an ACK - 32 s. When it fires the UAS "
                "declares the transaction failed and normally sends BYE, which is why unACKed calls die at 32 s.",
                "uas", "any"),
    "Timer I": ("T4 for UDP, 0s for TCP", T4, "17.2.1", "Absorbs ACK retransmissions.", "uas", "any"),
    "Timer J": ("64*T1 for UDP, 0s for TCP", 64 * T1, "17.2.2",
                "How long a non-INVITE server transaction absorbs request retransmissions.", "uas", "any"),
    "Timer K": ("T4 for UDP, 0s for TCP", T4, "17.1.2.2",
                "Absorbs retransmitted non-INVITE responses.", "uac", "any"),
}

# ---------------------------------------------------------------- failure catalog
# (id, category, severity, title, symptom, detection, root_causes, remediation, rfc_refs, confidence)
CHECKS: list[tuple] = [
    # --- capture quality ------------------------------------------------------
    ("CAP-DUPLICATE-FRAMES", "capture", "minor",
     "The capture contains the same frame more than once",
     "Messages appear twice with identical bytes, milliseconds apart - far faster than "
     "any retransmission timer allows.",
     "Two messages with the same 5-tuple and identical content, sharing a non-zero IPv4 "
     "identification field or arriving within 50 ms of each other. A genuine "
     "retransmission waits at least T1 (500 ms).",
     ["Port mirrored on both sides of a device, so each packet is seen twice",
      "A tap and a host capture merged into one file",
      "Capture on a bonded or bridged interface",
      "A log that records both the send and the receive of the same message"],
     "Harmless to the call, but it hides real retransmissions and inflates packet "
     "counts. Capture on one point, or de-duplicate before analysis. These frames "
     "were excluded from transaction analysis so retransmission checks stay accurate.",
     ["RFC3261#17.1.1.2", "RFC3261#18.2.1"], "high"),

    ("CAP-MULTIPLE-CAPTURE-POINTS", "capture", "minor",
     "The capture spans two points on the packet's path",
     "Every message appears twice with different addresses, and often a rewritten "
     "body - a capture taken either side of a NAT, SIP ALG or proxy.",
     "Two messages sharing Call-ID, CSeq, method or status and Via branch, arriving "
     "simultaneously, but with a different source or destination address - or with "
     "the same IPv4 identification field, which the sender assigns once and no "
     "intermediary rewrites. A retransmission keeps both addresses and gets a new id.",
     ["Capture taken before and after a NAT, merged into one file",
      "A SIP ALG rewriting addresses inside the message as it passes",
      "Capture on both the inside and outside interface of an SBC"],
     "This is a useful trace, not a fault: the two views together show exactly what "
     "the middlebox changed. The second view is excluded from transaction analysis so "
     "one message is not counted twice. Compare the pairs to see what was rewritten.",
     ["RFC3261#18.2.1", "RFC3261#16.6"], "medium"),

    # --- transactions and retransmission -------------------------------------
    ("SIP-ACK-MISSING", "signalling", "critical",
     "200 OK to INVITE never acknowledged",
     "The UAS keeps retransmitting 200 OK and the call drops about 32 s after answer.",
     "A 2xx to INVITE with no ACK carrying the same Call-ID and CSeq number within ~1 s, "
     "or any retransmission of that 2xx.",
     ["ACK routed by the Contact of the 200 OK, which is unreachable (NAT or private IP)",
      "Record-Route set not honoured, so the ACK went to the wrong hop",
      "SBC or firewall dropping the ACK", "UAC bug: no ACK generated for 2xx"],
     "Compare the Contact in the 200 OK with the address the ACK was sent to; verify the Route set "
     "derived from Record-Route in the 200 OK.",
     ["RFC3261#13.2.2.4", "RFC3261#17.1.1.3", "RFC3261#17.2.1"], "high"),

    ("SIP-2XX-RETRANSMIT", "signalling", "major",
     "Retransmitted 2xx final response to INVITE",
     "Multiple identical 200 OKs at roughly 0.5/1/2/4/4 s intervals.",
     "More than one 2xx with identical Call-ID, CSeq and to-tag.",
     ["ACK lost in transit", "UAC never generated the ACK"],
     "Follow SIP-ACK-MISSING. Timer G drives the retransmission; Timer H ends it at 32 s.",
     ["RFC3261#17.2.1", "RFC6026#7.1"], "high"),

    ("SIP-INVITE-RETRANSMIT-NO-RESPONSE", "signalling", "critical",
     "INVITE retransmitted with no response at all",
     "INVITE repeats at 0.5/1/2/4/8/16 s and the call ends in a locally-generated 408 at 32 s.",
     "Two or more identical INVITEs (same branch) with no response of any class in between.",
     ["Next hop unreachable or firewalled", "wrong destination IP or port from DNS/SRV",
      "peer dropping the request silently because the source IP is not whitelisted",
      "UDP fragmentation of a large INVITE"],
     "Check reachability of the next hop, the resolved target, and whether the INVITE exceeded the MTU.",
     ["RFC3261#17.1.1.2", "RFC3261#18.1.1"], "high"),

    ("SIP-NO-100-TRYING", "signalling", "minor",
     "No 100 Trying from the next hop",
     "The UAC retransmits its INVITE even though the far end is processing it.",
     "An INVITE over UDP with no 1xx within 500 ms, followed by a retransmission.",
     ["Stateless proxy not sending 100", "slow downstream lookup", "element under load"],
     "The next hop should send 100 Trying immediately when it cannot answer within 200 ms.",
     ["RFC3261#17.2.1", "RFC3261#13.3.1.1"], "high"),

    ("SIP-TIMER-B-TIMEOUT", "timer", "critical",
     "INVITE client transaction timed out (Timer B)",
     "Exactly ~32 s of INVITE retransmissions, then failure.",
     "Elapsed time between first INVITE and give-up is 64*T1 (32 s at default T1) with no final response.",
     ["Signalling path broken in one direction", "far end never answers the transaction"],
     "Treat the 408 as locally generated - the real fault is loss of the signalling path.",
     ["RFC3261#17.1.1.2"], "high"),

    ("SIP-TIMER-C-CANCEL", "timer", "major",
     "Proxy cancelled a stalled call (Timer C)",
     "A call sits in 180/183 for over 3 minutes and is then cancelled by an intermediary, "
     "producing a 487 the caller never requested.",
     "CANCEL/487 arriving >180 s after the last provisional, originated by a proxy rather than the UAC.",
     ["Callee never answered and no provisional refreshed the timer", "IVR or queue exceeding Timer C"],
     "Send periodic provisional responses to refresh Timer C, or raise it on the proxy.",
     ["RFC3261#16.6", "RFC3261#16.8"], "medium"),

    ("SIP-487-WITHOUT-CANCEL", "signalling", "minor",
     "487 Request Terminated with no matching CANCEL on this leg",
     "The INVITE is terminated but no CANCEL appears in this capture.",
     "A 487 whose Call-ID has no preceding CANCEL with the same branch.",
     ["Cancel generated upstream and not visible at this capture point",
      "forking: another branch answered and the proxy cancelled this one",
      "proxy Timer C expiry"],
     "Widen the capture, or correlate with the forking proxy's own trace.",
     ["RFC3261#9.1", "RFC3261#16.10"], "medium"),

    ("SIP-CANCEL-RACE", "signalling", "major",
     "CANCEL raced a 200 OK",
     "CANCEL is sent but the call still connects, or a 481 answers the CANCEL.",
     "A CANCEL sent after a 2xx for the same INVITE transaction, or a CANCEL answered 481.",
     ["Caller hung up in the same instant the callee answered"],
     "Once a 2xx exists the CANCEL is ineffective; the UAC must ACK and then send BYE.",
     ["RFC3261#9.1", "RFC3261#15"], "high"),

    ("SIP-NON-2XX-NOT-ACKED", "signalling", "major",
     "Non-2xx final response not acknowledged",
     "The UAS retransmits a 4xx/5xx/6xx final response.",
     "A non-2xx final with no ACK carrying the same branch, or repeated finals.",
     ["Transaction layer bug at the UAC", "ACK lost hop-by-hop"],
     "Non-2xx finals are ACKed hop-by-hop by the transaction layer, using the same branch as the INVITE.",
     ["RFC3261#17.1.1.3", "RFC3261#17.2.1"], "high"),

    ("SIP-491-GLARE", "signalling", "minor",
     "Re-INVITE glare (491 Request Pending)",
     "Both parties modify the session at once; one gets 491.",
     "A 491 in response to an in-dialog INVITE, or a re-INVITE sent while another INVITE transaction "
     "is outstanding in either direction.",
     ["Simultaneous hold and codec renegotiation", "session-timer refresh colliding with a re-INVITE"],
     "Back off and retry: 2.1-4 s if you own the Call-ID, 0-2 s if not. Repeated 491s mean one side is not backing off.",
     ["RFC3261#14.1", "RFC3261#14.2"], "high"),

    ("SIP-CSEQ-NOT-INCREMENTED", "signalling", "major",
     "CSeq not incremented for a new request in the dialog",
     "The peer answers 500, ignores the request, or treats it as a retransmission.",
     "Two different in-dialog requests with the same CSeq number and method but different content.",
     ["UA bug", "re-sent request after auth challenge without incrementing"],
     "Every new request within a dialog must use a CSeq strictly greater than the last, ACK and CANCEL excepted.",
     ["RFC3261#12.2.1.1", "RFC3261#8.1.3.5"], "high"),

    ("SIP-BRANCH-NOT-RFC3261", "interop", "minor",
     "Via branch lacks the z9hG4bK magic cookie",
     "Transaction matching falls back to the RFC 2543 rules; odd matching failures follow.",
     "A top Via branch parameter that does not start with z9hG4bK.",
     ["Very old UA or gateway", "branch rewritten by a broken B2BUA"],
     "Every RFC 3261 element must begin the branch with z9hG4bK and make it unique per transaction.",
     ["RFC3261#8.1.1.7", "RFC3261#17.2.3"], "high"),

    ("SIP-BRANCH-REUSED", "signalling", "major",
     "Via branch reused across different transactions",
     "Responses match the wrong request; requests are mistaken for retransmissions.",
     "The same top-Via branch on two requests that differ in method (other than ACK/CANCEL) or in Request-URI.",
     ["B2BUA generating non-unique branches", "load balancer rewriting Via badly"],
     "The branch must be unique across space and time for every distinct transaction.",
     ["RFC3261#8.1.1.7"], "high"),

    ("SIP-MERGED-REQUEST", "routing", "minor",
     "Merged request (forked INVITE arriving twice)",
     "The UAS receives the same request over two paths and answers 482 to the second.",
     "Two requests with identical Call-ID, From tag and CSeq but different top-Via branches.",
     ["Forking proxy with two routes to the same UA", "duplicate registration bindings"],
     "The UAS must answer 482 to the second copy; the real fix is removing the duplicate route.",
     ["RFC3261#8.2.2.2"], "high"),

    # --- routing -------------------------------------------------------------
    ("SIP-RECORD-ROUTE-ASYMMETRY", "routing", "major",
     "Record-Route set differs between provisional and final response",
     "The call sets up but in-dialog requests (BYE, re-INVITE) get 481 or vanish.",
     "The Record-Route header list in the 18x differs from the one in the 2xx for the same dialog.",
     ["B2BUA rewriting Record-Route inconsistently", "proxy adding Record-Route only on some responses"],
     "The Route set is taken from the dialog-establishing response and must be stable.",
     ["RFC3261#12.1.1", "RFC3261#12.1.2", "RFC3261#16.6"], "high"),

    ("SIP-NO-ROUTE-IN-DIALOG", "routing", "major",
     "In-dialog request sent without the Route set",
     "BYE or re-INVITE is answered 404/481, or never reaches the peer.",
     "The dialog-forming response carried Record-Route, but a later in-dialog request has no matching Route headers.",
     ["UA ignoring Record-Route", "Route set built from the wrong response"],
     "Build the Route set from the Record-Route of the dialog-establishing response, reversed for the UAC.",
     ["RFC3261#12.1.1", "RFC3261#12.2.1.1"], "high"),

    ("SIP-CONTACT-PRIVATE-ADDRESS", "nat", "critical",
     "Contact contains a private address on a public path",
     "Setup works but ACK, BYE or re-INVITE is black-holed; the call drops at 32 s or never tears down.",
     "A Contact URI host in 10/8, 172.16/12, 192.168/16 or 100.64/10 while the packet source is public.",
     ["UA behind NAT with no far-end NAT traversal", "SBC not rewriting Contact",
      "outbound/rport not in use"],
     "Rewrite Contact at the SBC, or use RFC 5626 outbound with a flow token.",
     ["RFC3261#8.1.1.8", "RFC3261#12.1.1", "RFC5626#4.2.1"], "high"),

    ("SIP-VIA-RECEIVED-MISMATCH", "nat", "major",
     "Via sent-by does not match the packet source and no received parameter was added",
     "Responses are sent to an unreachable address and the far end sees no answer.",
     "Top Via host differs from the IP source address of the request, with no received= parameter.",
     ["Server not adding received= as required", "UA advertising an address it does not own"],
     "A server must add received= whenever the sent-by host differs from the source address.",
     ["RFC3261#18.2.1", "RFC3261#20.42"], "high"),

    ("SIP-NO-RPORT", "nat", "minor",
     "No rport in use behind NAT",
     "Responses go to the port in Via rather than the port the NAT actually mapped, and are dropped.",
     "A request from a NATed source whose top Via has no rport parameter.",
     ["UA does not implement RFC 3581", "rport stripped by an intermediary"],
     "Enable symmetric response routing (rport) on the client and honour it on the server.",
     ["RFC3581#4"], "high"),

    ("SIP-UDP-OVERSIZE", "transport", "major",
     "SIP message over UDP close to or above the path MTU",
     "The message is fragmented and often dropped, producing retransmissions and 513.",
     "A UDP-carried SIP message within 200 bytes of the MTU (default threshold 1300 bytes).",
     ["Large SDP with many codecs or ICE candidates", "long header stacks after several hops"],
     "Switch that hop to TCP, as required once the message approaches the MTU.",
     ["RFC3261#18.1.1"], "high"),

    ("SIP-MAX-FORWARDS-MISSING", "routing", "minor",
     "Request originated with no Max-Forwards header",
     "Nothing visibly fails. RFC 3261 section 16.3 passes a request with no Max-Forwards "
     "explicitly, and section 16.6 has the next proxy insert one, so the call completes "
     "and the violation only shows up when you read the request.",
     "A request carrying no Max-Forwards header field, which section 8.1.1.6 makes "
     "mandatory for every request a UAC originates. Reported once per sending address "
     "rather than once per request - section 16.6 notes plainly that some existing UAs do "
     "not provide it, so a single such UA would otherwise fill the report. The finding "
     "also says whether a proxy in the same capture repaired it, which is the difference "
     "between a cosmetic violation and a request with no hop counter on its path.",
     ["UA firmware that omits the header entirely",
      "sipp or another test tool using a hand-written scenario file",
      "a B2BUA regenerating requests without one, although section 20.22 says it should "
      "insert one precisely because it cannot otherwise guarantee loop detection",
      "SBC or gateway rebuilding the request from scratch"],
     "Harmless wherever a compliant proxy is in the path, because it must add the header "
     "before forwarding. It matters where no element does: direct UA-to-UA calls and "
     "non-compliant B2BUAs, where the request travels with no hop counter and a routing "
     "loop can then only be caught by the optional Via loop detection of section 16.3 "
     "step 4. Fix it at the origin - the recommended starting value is 70.",
     ["RFC3261#8.1.1.6", "RFC3261#16.6", "RFC3261#16.3", "RFC3261#20.22"], "high"),

    ("SIP-MAX-FORWARDS-LOW", "routing", "minor",
     "Max-Forwards started well below 70",
     "Long but legitimate routing chains fail with 483.",
     "An initial request whose Max-Forwards is materially below the recommended 70.",
     ["Misconfigured origin", "device defaulting to a low value"],
     "Set Max-Forwards to 70 on originating requests.",
     ["RFC3261#8.1.1.6", "RFC3261#20.22"], "high"),

    ("SIP-VIA-LOOP", "routing", "critical",
     "Routing loop visible in the Via stack",
     "The call fails with 482 or 483 after bouncing between elements.",
     "The same host appears more than once in the Via stack of a single request.",
     ["Two proxies each treating the other as the route of last resort",
      "redirect pointing back into the originating proxy", "registration binding pointing at the proxy itself"],
     "Break the loop in the routing logic; 483 and 482 are symptoms, not causes.",
     ["RFC3261#16.3", "RFC3261#16.6"], "high"),

    # --- authentication ------------------------------------------------------
    ("SIP-AUTH-LOOP", "auth", "major",
     "Repeated authentication challenges for the same request",
     "401 or 407 is issued more than once for the same Call-ID and the request never succeeds.",
     "Two or more 401/407 responses within one Call-ID for the same method.",
     ["Wrong password", "realm mismatch between config and challenge",
      "algorithm mismatch (server offers SHA-256, client only does MD5)",
      "credentials placed in Authorization when the challenge came from a proxy (or vice versa)",
      "UA not incrementing CSeq on the authenticated retry"],
     "Compare realm, nonce, algorithm and qop between challenge and response; verify the retry increments CSeq "
     "and uses the header matching the challenge type.",
     ["RFC3261#22.2", "RFC3261#22.3", "RFC8760#2"], "high"),

    ("SIP-AUTH-WRONG-HEADER", "auth", "major",
     "Credentials returned in the wrong authorization header",
     "Authentication never succeeds even though the password is right.",
     "A 407 answered with Authorization, or a 401 answered with Proxy-Authorization.",
     ["UA does not distinguish proxy challenges from endpoint challenges"],
     "A 401 is answered with Authorization; a 407 is answered with Proxy-Authorization.",
     ["RFC3261#22.2", "RFC3261#22.3"], "high"),

    ("SIP-IN-DIALOG-481", "signalling", "major",
     "In-dialog request rejected with 481",
     "A BYE, re-INVITE or UPDATE is answered 481 Call/Transaction Does Not Exist.",
     "A 481 response to any in-dialog request.",
     ["Peer already tore the dialog down", "wrong To/From tag on the request",
      "dialog state lost on a restarted or failed-over server",
      "Route set wrong, so the request reached an element that never had the dialog"],
     "Compare Call-ID and both tags against the dialog-establishing 200 OK, and check the Route "
     "set against its Record-Route.",
     ["RFC3261#12.2.1.2", "RFC3261#21.4.19"], "high"),

    ("SIP-NON-INVITE-FAILED", "signalling", "major",
     "Non-INVITE transaction ended in a permanent failure",
     "A REGISTER, SUBSCRIBE, PUBLISH, NOTIFY, REFER, OPTIONS or BYE was answered 4xx or "
     "5xx and never succeeded. No call is involved, so nothing about the trace looks "
     "wrong until you read the response code: the phone shows 'registration failed', a "
     "BLF lamp never lights, or a mailbox never notifies.",
     "A transaction whose method is not INVITE, ACK or CANCEL and whose first final "
     "response is 400-599. A 401 or 407 answered by a retry carrying credentials is "
     "ordinary digest authentication and is excluded; a challenge that repeats within one "
     "Call-ID is SIP-AUTH-LOOP's finding, and a challenge at the very end of the capture "
     "is treated as truncation rather than as failure. Codes with a check of their own "
     "(420, 422, 423, 481, 488, 491) are left to it. Repeats of the same refusal - same "
     "method, code, AoR and event package - are reported once with a count, because a "
     "client retrying a request its peer will never accept opens a fresh Call-ID every "
     "time. The response code's own catalog entry carries the diagnosis; this check only "
     "says which transaction died on it.",
     ["Wrong password or wrong user, refused 403 or 404 after the first challenge",
      "AoR or number not provisioned on the registrar",
      "SUBSCRIBE for an event package the notifier does not implement (489)",
      "SUBSCRIBE or PUBLISH for a resource that does not exist, such as a mailbox (404)",
      "Source IP outside the peer's ACL, or the trunk not provisioned (403)",
      "Callee temporarily unavailable or out of service (480)",
      "Server-side fault on the registrar, presence server or state agent (5xx)"],
     "Read the meaning attached to the response code, then decide from it: a 403 is "
     "policy, a 404 is provisioning, a 489 is an unsupported event package and a 5xx is "
     "the peer's own fault. For a failed REGISTER, compare the credentials, realm and AoR "
     "against what the registrar expects; for a failed SUBSCRIBE, compare the Event header "
     "against the peer's Allow-Events.",
     ["RFC3261#21", "RFC3261#21.4", "RFC3261#21.5", "RFC3261#17.1.2.2",
      "RFC3265#3.1.4.1", "RFC3903#5"], "high"),

    ("SIP-AUTH-STALE-NONCE", "auth", "minor",
     "Challenge with stale=true",
     "An otherwise valid request is challenged again because the nonce aged out.",
     "A 401/407 whose WWW-Authenticate or Proxy-Authenticate carries stale=true.",
     ["Nonce lifetime shorter than the client's retry interval", "clock skew"],
     "The client should retry with a fresh nonce and the same credentials - this is not a password failure.",
     ["RFC3261#22.2"], "high"),

    # --- registration --------------------------------------------------------
    ("SIP-REGISTER-423-LOOP", "registration", "minor",
     "Registration rejected as too brief, repeatedly",
     "REGISTER is answered 423 more than once for the same AoR.",
     "Two or more 423 responses for the same AoR, or a retry whose Expires is still below Min-Expires.",
     ["Client ignoring Min-Expires in the 423", "hard-coded short expiry"],
     "Retry with Expires at least equal to the Min-Expires in the 423.",
     ["RFC3261#10.2.8", "RFC3261#10.3"], "high"),

    ("SIP-REGISTER-EXPIRY-EXCEEDS-NAT", "nat", "major",
     "Registration refresh interval longer than a typical NAT binding",
     "Inbound calls fail until the client re-registers; outbound calls work.",
     "A granted registration expiry above ~120 s over UDP from a NATed client with no keepalives.",
     ["Registrar granting a long expiry", "no CRLF keepalive or OPTIONS ping"],
     "Shorten the granted expiry or run RFC 5626 keepalives to hold the binding open.",
     ["RFC5626#3.5", "RFC5626#4.4.1"], "medium"),

    ("SIP-REGISTER-FLAPPING", "registration", "minor",
     "Registration re-established far more often than the granted expiry",
     "Frequent REGISTER traffic with changing Call-IDs.",
     "REGISTER intervals well below the granted expiry, with a new Call-ID each time.",
     ["Client restarting", "network path flapping", "registrar dropping bindings early"],
     "Compare the granted Expires with the observed refresh interval.",
     ["RFC3261#10.2.4"], "medium"),

    # --- offer / answer ------------------------------------------------------
    ("SDP-ANSWER-MISSING", "media", "critical",
     "Offer sent but no answer in the dialog-establishing response",
     "The call connects with no media, or the UAC tears it down.",
     "An INVITE carrying SDP whose 2xx has no SDP body.",
     ["B2BUA stripping the body", "UAS bug", "media server failure"],
     "The answer must appear in the first reliable non-failure response, or in the ACK when the INVITE was offerless.",
     ["RFC3261#13.2.1", "RFC3264#5", "RFC6337#3.1.1"], "high"),

    ("SDP-OFFERLESS-INVITE-NO-ACK-ANSWER", "media", "major",
     "Offerless INVITE answered but the ACK carries no offer",
     "Media never starts after an INVITE sent without SDP.",
     "An INVITE with no body, a 2xx with SDP, and an ACK with no body.",
     ["UAC does not support offerless INVITE (3pcc)"],
     "When the INVITE has no offer, the 2xx carries the offer and the ACK must carry the answer.",
     ["RFC3261#13.2.1", "RFC3264#6", "RFC3725#4"], "high"),

    ("SDP-CODEC-MISMATCH", "media", "major",
     "No codec in common between offer and answer",
     "The call is rejected with 488 Not Acceptable Here, or 606.",
     "A 488/606 to an INVITE, or an answer whose m= line shares no payload type with the offer.",
     ["Disjoint codec lists", "transcoding disabled on the SBC",
      "peer expects G.729 while only G.711 is offered"],
     "Align the codec lists or enable transcoding. Compare the m= payload lists and a=rtpmap of both sides.",
     ["RFC3264#6.1", "RFC3261#21.4.26"], "high"),

    ("SDP-TRANSPORT-PROFILE-MISMATCH", "media", "major",
     "Media transport profile mismatch (RTP/AVP vs RTP/SAVP)",
     "The call is rejected with 488, or connects silently with no decodable audio.",
     "The m= line proto in the answer differs from the offer, or SRTP crypto attributes appear on only one side.",
     ["SRTP mandatory on one side and unavailable on the other",
      "DTLS-SRTP offered to an SDES-only peer", "SBC not bridging secure and insecure legs"],
     "Match the profile end to end or terminate SRTP at the SBC.",
     ["RFC3264#5.1", "RFC3711#5"], "high"),

    ("SDP-DIRECTION-MISMATCH", "media", "major",
     "Direction attributes are not complementary",
     "One-way audio.",
     "sendonly in the offer without recvonly in the answer, or both sides claiming sendonly / recvonly.",
     ["Hold implemented inconsistently", "B2BUA rewriting direction attributes"],
     "sendonly must be answered with recvonly, recvonly with sendonly, sendrecv with sendrecv or a subset.",
     ["RFC3264#6.1", "RFC8866#6.7"], "high"),

    ("SDP-PRIVATE-MEDIA-ADDRESS", "nat", "critical",
     "SDP connection address is private on a public path",
     "One-way or no audio, while signalling looks perfect.",
     "A c= line in 10/8, 172.16/12, 192.168/16 or 100.64/10 while the signalling peer is public.",
     ["UA behind NAT with no media relay", "SBC not performing media latching or NAT rewriting"],
     "Relay media through the SBC, or use ICE/STUN so the public candidate is offered.",
     ["RFC8866#5.7", "RFC3264#5.1"], "high"),

    ("SDP-PORT-ZERO", "media", "minor",
     "Media stream disabled with port 0",
     "A stream that was offered is absent from the call.",
     "An m= line with port 0 in the answer.",
     ["Peer rejecting video or T.38 while accepting audio", "normal stream removal in a re-INVITE"],
     "Expected when a stream is deliberately declined; the m= line must still be present and in the same order.",
     ["RFC3264#6", "RFC8866#5.14"], "high"),

    ("SDP-HOLD-INCONSISTENT", "media", "minor",
     "Hold signalled inconsistently (c=0.0.0.0 versus a=sendonly)",
     "Music on hold is missing, or audio does not resume after retrieve.",
     "A re-INVITE using the legacy c=0.0.0.0 form mixed with direction-attribute hold across the same dialog.",
     ["Old UA using RFC 2543 style hold", "B2BUA translating hold badly"],
     "Prefer a=sendonly/a=inactive; keep the same convention for hold and retrieve.",
     ["RFC3264#8.4", "RFC6337#5.3"], "medium"),

    ("SDP-VERSION-NOT-INCREMENTED", "media", "minor",
     "SDP changed but the o= version did not increase",
     "The peer ignores the change - hold or codec change has no effect.",
     "Two SDP bodies in one dialog with the same o= session version but different content.",
     ["UA bug"],
     "Increment the version field of o= whenever the description changes; keep it identical when re-sending unchanged.",
     ["RFC3264#8", "RFC8866#5.2"], "high"),

    ("SDP-DTMF-MISMATCH", "media", "major",
     "Negotiated DTMF method differs between the legs",
     "IVR menus do not respond to keypresses.",
     "telephone-event present in one direction only, or different payload numbers with no rtpmap agreement.",
     ["One side sends RFC 4733 while the other expects INFO or inband",
      "payload type renumbered by an SBC without rewriting the RTP"],
     "Ensure telephone-event is negotiated symmetrically, and that the payload number used in RTP matches the answer.",
     ["RFC4733#2.4", "RFC3264#6.1"], "high"),

    ("SDP-MULTIPLE-STREAMS-REORDERED", "media", "major",
     "Media lines reordered between offer and answer",
     "Audio and video get crossed, or a stream is silently dropped.",
     "The answer's m= lines are not in the same order and count as the offer's.",
     ["Non-compliant UA or B2BUA"],
     "The answer must contain the same number of m= lines in the same order; unwanted ones get port 0.",
     ["RFC3264#6"], "high"),

    # --- reliability of provisionals ----------------------------------------
    ("SIP-PRACK-MISSING", "signalling", "major",
     "Reliable provisional response never PRACKed",
     "A 18x with Require: 100rel is retransmitted repeatedly.",
     "A provisional carrying Require: 100rel and RSeq, with no PRACK whose RAck matches.",
     ["Peer does not support 100rel but did not reject it", "PRACK lost", "RAck mismatch"],
     "The UAC must PRACK a reliable provisional; the UAS retransmits it with exponential backoff until it does.",
     ["RFC3262#3", "RFC3262#4"], "high"),

    ("SIP-100REL-UNSUPPORTED", "interop", "minor",
     "100rel required but not supported",
     "The INVITE is rejected with 420 Bad Extension naming 100rel.",
     "A 420 whose Unsupported header contains 100rel.",
     ["Require: 100rel sent to a UA without PRACK support"],
     "Move 100rel from Require to Supported, or disable it toward that peer.",
     ["RFC3262#3", "RFC3261#20.40"], "high"),

    # --- session timers ------------------------------------------------------
    ("SIP-SESSION-TIMER-422-LOOP", "timer", "major",
     "Session-Expires below the peer's Min-SE, repeatedly",
     "The INVITE is rejected with 422 more than once.",
     "Two or more 422 responses in one Call-ID, or a retry whose Session-Expires is still below the advertised Min-SE.",
     ["Client ignoring Min-SE in the 422", "hard-coded Session-Expires"],
     "Read Min-SE from the 422 and retry with at least that value.",
     ["RFC4028#6", "RFC4028#7.2"], "high"),

    ("SIP-SESSION-TIMER-NO-REFRESH", "timer", "major",
     "Session timer negotiated but never refreshed",
     "The call drops at exactly the Session-Expires value - the classic 30-minute cutoff.",
     "A dialog with Session-Expires whose refresher sent no re-INVITE or UPDATE before expiry.",
     ["Refresher role misunderstood between the two sides",
      "refresh blocked by an intermediary", "B2BUA not propagating the refresh"],
     "Confirm which side is the refresher (refresher=uac|uas) and that it refreshes at half the interval.",
     ["RFC4028#7.1", "RFC4028#10"], "high"),

    # --- transfer ------------------------------------------------------------
    ("SIP-REFER-NO-NOTIFY", "signalling", "major",
     "REFER accepted but no NOTIFY of progress",
     "The transferor never learns whether the transfer worked and may leave the call hanging.",
     "A 2xx to REFER with no subsequent NOTIFY carrying a message/sipfrag body.",
     ["Transferee does not implement the implicit subscription", "NOTIFY blocked by an intermediary"],
     "The transferee must send an immediate NOTIFY (100 Trying sipfrag) and a final one with the outcome.",
     ["RFC3515#2.4.4", "RFC3515#2.4.5"], "high"),

    ("SIP-REPLACES-NO-DIALOG", "signalling", "major",
     "Replaces refers to a dialog that does not exist",
     "Attended transfer fails with 481.",
     "An INVITE with a Replaces header answered 481 or 603.",
     ["Target dialog already terminated", "wrong to-tag/from-tag in Replaces",
      "the dialog lives on a different server in a cluster"],
     "Check that the Call-ID and both tags in Replaces match a live dialog on the receiving element.",
     ["RFC3891#3"], "high"),

    # --- media plane ---------------------------------------------------------
    ("RTP-NO-STREAM", "media", "critical",
     "Media negotiated but no RTP observed",
     "Total silence on an otherwise perfect call.",
     "A dialog with a completed offer/answer and no RTP packets to the negotiated address and port.",
     ["Firewall blocking the RTP range", "media address unreachable (see SDP-PRIVATE-MEDIA-ADDRESS)",
      "media server not started", "capture point not on the media path"],
     "Confirm the capture covers the media path, then test reachability of the negotiated address and port.",
     ["RFC3550#3", "RFC3264#5.1"], "high"),

    ("RTP-ONE-WAY", "media", "critical",
     "RTP flowing in one direction only",
     "One party hears the other but not the reverse.",
     "RTP present from A to B for the negotiated stream, with none from B to A.",
     ["NAT with no symmetric RTP or latching on one side",
      "asymmetric firewall rules", "one side answered with a private or wrong address"],
     "Compare each side's advertised media address with the source address of the RTP actually received.",
     ["RFC3550#3", "RFC3264#5.1"], "high"),

    ("RTP-PAYLOAD-NOT-NEGOTIATED", "media", "major",
     "RTP payload type was never negotiated",
     "Distorted audio or silence despite RTP flowing.",
     "An RTP payload type absent from the answer's m= line for that stream.",
     ["Sender ignoring the answer", "payload renumbering by an SBC that did not rewrite the RTP",
      "dynamic payload type collision"],
     "Only send payload types present in the answer; check dynamic payload numbering (96-127) on both legs.",
     ["RFC3550#5.1", "RFC3264#6.1"], "high"),

    ("RTP-SSRC-CHANGE", "media", "minor",
     "SSRC changed mid-stream without a re-INVITE",
     "A click, a gap, or a jitter-buffer reset mid-call.",
     "The SSRC of a stream changes with no intervening re-INVITE or UPDATE.",
     ["Media server switching source (announcement, MoH)", "SSRC collision", "SBC failover"],
     "Expected across a media-server change; unexpected mid-conversation it points at a relay switching path.",
     ["RFC3550#8.2"], "medium"),

    ("RTP-SEQUENCE-GAP", "media", "major",
     "RTP sequence gaps indicating packet loss",
     "Choppy or robotic audio.",
     "Missing RTP sequence numbers beyond reordering tolerance in a stream.",
     ["Network congestion", "undersized jitter buffer upstream", "wireless loss", "policer dropping media"],
     "Quantify loss per direction and correlate with RTCP receiver reports.",
     ["RFC3550#6.4.1", "RFC3550#A.3"], "high"),

    ("RTP-TIMESTAMP-JUMP", "media", "minor",
     "RTP timestamp discontinuity",
     "Audio speeds up, slows down, or the jitter buffer resets.",
     "A timestamp step inconsistent with the payload's clock rate and the packet interval.",
     ["Encoder restart", "media path switch", "comfort-noise or DTMF interleaving handled badly"],
     "Compare the timestamp delta with ptime multiplied by the clock rate for that payload.",
     ["RFC3550#5.1"], "medium"),

    ("RTCP-ABSENT", "media", "minor",
     "No RTCP for a long-running stream",
     "No quality telemetry, and some peers tear the call down on missing RTCP.",
     "A stream running longer than ~30 s with no RTCP packets on the paired port.",
     ["RTCP blocked by a firewall", "RTCP disabled", "rtcp-mux assumed by only one side"],
     "Open the RTCP port or negotiate rtcp-mux explicitly.",
     ["RFC3550#6.2"], "medium"),

    ("RTP-JITTER-HIGH", "media", "major",
     "Interarrival jitter above the usable range",
     "Warbling audio and jitter-buffer overruns.",
     "Interarrival jitter, computed as in RFC 3550, persistently above roughly 30 ms.",
     ["Congested or variable-latency path", "wireless access", "over-subscribed uplink"],
     "Compute jitter per direction as RFC 3550 defines it and correlate with RTCP reports.",
     ["RFC3550#6.4.1", "RFC3550#A.8"], "high"),
]

# ---------------------------------------------------------------- interop lore
NOTES: list[tuple] = [
    ("timers", "The default T1 of 500 ms makes 32 s (64*T1) the single most common failure interval in SIP. "
     "A call that dies at ~32 s after answer means an ACK problem (Timer H); a setup that fails at ~32 s "
     "means the INVITE transaction timed out (Timer B).", ["RFC3261#17.1.1.2", "RFC3261#17.2.1"], "RFC 3261 Table 4"),
    ("ack", "ACK for a 2xx is a separate transaction with its own branch, generated by the UAC core and routed "
     "end to end by the Route set. ACK for a non-2xx is generated by the transaction layer, reuses the INVITE's "
     "branch, and travels hop by hop. Diagnosing a missing ACK starts with deciding which of the two is missing.",
     ["RFC3261#13.2.2.4", "RFC3261#17.1.1.3"], "RFC 3261"),
    ("offer-answer", "The offer can be in the INVITE, in a reliable provisional, in the 2xx, or in the ACK. "
     "Any diagnosis that assumes 'offer in INVITE, answer in 200' will misread 3pcc and early-media flows.",
     ["RFC3264#5", "RFC3725#4", "RFC6337#3.1.2"], "RFC 3264/3725/6337"),
    ("early-media", "Renegotiating during an early dialog requires UPDATE, not re-INVITE: a UA must not send "
     "a re-INVITE before the initial INVITE gets a final response.",
     ["RFC3311#1", "RFC3261#14.1"], "RFC 3311"),
    ("nat", "The three addresses that must all be reachable are the Via (responses), the Contact (in-dialog "
     "requests) and the SDP c= line (media). NAT problems are almost always one of these three being private "
     "while the others are public - which is why signalling can succeed while media fails, or setup can succeed "
     "while teardown fails.", ["RFC3261#8.1.1.7", "RFC3261#8.1.1.8", "RFC8866#5.7"], "operational"),
    ("forking", "A forked INVITE creates one early dialog per branch, each with its own to-tag. Provisionals "
     "from different branches share a Call-ID and From tag, so correlating by Call-ID alone will merge unrelated "
     "branches into one nonsensical flow.", ["RFC3261#13.2.2.4", "RFC3261#16.7"], "RFC 3261"),
    ("cancel", "CANCEL is hop-by-hop and matched to the INVITE by branch, and it never applies once a 2xx exists. "
     "A CANCEL answered 200 means the CANCEL itself was accepted, not that the call was cancelled - the "
     "confirmation is the 487 on the INVITE transaction.", ["RFC3261#9.1", "RFC3261#9.2"], "RFC 3261"),
    ("b2bua", "A B2BUA breaks every end-to-end assumption: Call-ID, tags, branches and SDP all change across it. "
     "Correlating the two legs needs a shared identifier such as time proximity, the called number, or a "
     "vendor header - never the Call-ID.", [], "operational"),
]

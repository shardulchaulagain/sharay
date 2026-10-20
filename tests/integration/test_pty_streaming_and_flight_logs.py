"""Unit and integration test suite for Sector 8: Hardened PTY Streaming & Replayable Flight Logs.

Proves:
1. Resumable PTY buffer with precise cursor offset tracking and disconnect/resume.
2. Binary-safe ANSI sanitization (strips OSC 52 clipboard hijacking, preserves safe colors).
3. Cryptographically chained courtroom-grade flight logs with tamper detection.
4. Asciinema v2 export and deterministic session replaying.
"""

from __future__ import annotations

import json

from aegis.interactive import (
    FlightLogReplayer,
    ReplayableFlightLogRecorder,
    ResumablePTYBuffer,
    sanitize_terminal_stream,
)


def test_resumable_pty_buffer_resume_and_reconnect():
    """Verify that a client can reconnect and resume streaming without data loss or duplication."""
    buf = ResumablePTYBuffer(capacity_bytes=10000)

    # Initial write
    buf.write(b"sharay> probe https://target.local\r\n")
    buf.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n")

    # Client reads first batch from offset 0
    chunk1, next_offset1 = buf.read_from_offset(0)
    assert b"sharay> probe" in chunk1
    assert next_offset1 > 0

    # Command completes while client is offline / disconnected
    buf.write(b'{"status": "healthy"}\r\nsharay> ')

    # Client reconnects with next_offset1
    chunk2, next_offset2 = buf.read_from_offset(next_offset1)
    assert b'{"status": "healthy"}' in chunk2
    # Ensure chunk2 does NOT re-send earlier headers
    assert b"HTTP/1.1 200 OK" not in chunk2
    assert next_offset2 > next_offset1

    # Client requests from current tail offset -> empty chunk
    chunk3, next_offset3 = buf.read_from_offset(next_offset2)
    assert chunk3 == b""
    assert next_offset3 == next_offset2


def test_ansi_escape_sanitization():
    """Verify dangerous OSC escape sequences are stripped while safe ANSI colors remain."""
    # Safe ANSI: green text
    safe_ansi = b"\x1b[32m[PASS] Security Check\x1b[0m\r\n"
    assert sanitize_terminal_stream(safe_ansi) == safe_ansi

    # Dangerous OSC 52 clipboard hijack payload
    malicious = b"\x1b]52;c;ZXhwbG9pdA==\x07\x1b[31m[VULN] Detected\x1b[0m\r\n"
    sanitized = sanitize_terminal_stream(malicious)
    assert b"52;c;" not in sanitized
    assert b"\x1b[31m[VULN] Detected\x1b[0m" in sanitized


def test_flight_log_recorder_integrity_and_tamper_detection():
    """Verify cryptographically chained flight logs detect record tampering."""
    recorder = ReplayableFlightLogRecorder("sess-123", "operator-alice")

    t0 = 1000.0
    recorder.record("stdin", "whoami\n", timestamp=t0)
    recorder.record("stdout", "operator: alice (owner)\n", timestamp=t0 + 0.1)
    recorder.record("stdin", "poc fp-sqli-01\n", timestamp=t0 + 1.5)
    recorder.record("stdout", "[AutoPyVerifier] Exit code: 0 (REPRODUCED)\n", timestamp=t0 + 2.0)

    # Valid chain check
    valid, msg = recorder.verify_integrity()
    assert valid is True
    assert "4 entries intact" in msg

    # Adversarial tampering: alter output text of entry 3
    recorder.entries[3].data = "[AutoPyVerifier] Exit code: 1 (FAILED)\n"

    # Verification must fail fail-closed
    valid, err_msg = recorder.verify_integrity()
    assert valid is False
    assert "Entry hash tampered at index 3" in err_msg


def test_flight_log_asciinema_v2_export_and_replay():
    """Verify asciinema v2 JSONL export and deterministic playback."""
    recorder = ReplayableFlightLogRecorder("sess-456", "operator-bob")
    t0 = 2000.0
    recorder.record("stdin", "help\n", timestamp=t0)
    recorder.record("stdout", "Commands: probe, dns, ssl, msf, poc\n", timestamp=t0 + 0.5)

    # Export asciinema v2
    asciinema_jsonl = recorder.export_asciinema_v2()
    lines = asciinema_jsonl.strip().splitlines()
    assert len(lines) == 3

    # Check header
    header = json.loads(lines[0])
    assert header["version"] == 2
    assert "SHARAY Operator Session sess-456" in header["title"]

    # Check event lines
    event_1 = json.loads(lines[1])
    assert event_1[0] == 0.0  # relative timestamp
    assert event_1[1] == "i"  # stdin
    assert event_1[2] == "help\n"

    event_2 = json.loads(lines[2])
    assert event_2[0] == 0.5
    assert event_2[1] == "o"  # stdout

    # Test replayer
    replayed = list(FlightLogReplayer.replay(recorder.entries, playback_speed=2.0))
    assert len(replayed) == 2
    # At 2.0x playback speed, 0.5s elapsed time is yielded as 0.25s
    assert replayed[1][0] == 0.25
    assert replayed[1][1] == "stdout"

"""Testes do log-forensics com um log de exemplo embutido."""

from __future__ import annotations

from logforensics import core
from logforensics.cli import main

SAMPLE_LOG = """\
Jul 10 10:00:01 host sshd[100]: Failed password for root from 203.0.113.5 port 22 ssh2
Jul 10 10:00:02 host sshd[101]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2
Jul 10 10:00:03 host sshd[102]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2
Jul 10 10:00:04 host sshd[103]: Failed password for invalid user test from 203.0.113.5 port 22 ssh2
Jul 10 10:00:05 host sshd[104]: Failed password for invalid user guest from 203.0.113.5 port 22 ssh2
Jul 10 10:00:06 host sshd[105]: Failed password for root from 203.0.113.5 port 22 ssh2
Jul 10 10:00:07 host sshd[106]: Failed password for root from 203.0.113.5 port 22 ssh2
Jul 10 10:00:08 host sshd[107]: Failed password for root from 203.0.113.5 port 22 ssh2
Jul 10 10:00:09 host sshd[108]: Accepted password for alice from 198.51.100.7 port 22 ssh2
Jul 10 10:00:10 host sshd[109]: root login accepted for 203.0.113.5
"""


def test_bruteforce_detected():
    report = core.analyze(SAMPLE_LOG.splitlines(), bruteforce_threshold=5)
    types = {i["type"] for i in report["indicators"]}
    assert "bruteforce_ssh" in types
    bf = [i for i in report["indicators"] if i["type"] == "bruteforce_ssh"]
    assert bf[0]["ip"] == "203.0.113.5"
    assert bf[0]["count"] == 8


def test_user_scanning_detected():
    report = core.analyze(SAMPLE_LOG.splitlines())
    scan = [i for i in report["indicators"] if i["type"] == "user_scanning"]
    assert scan and scan[0]["ip"] == "203.0.113.5"


def test_root_login_detected():
    report = core.analyze(SAMPLE_LOG.splitlines())
    root = [i for i in report["indicators"] if i["type"] == "root_login"]
    assert root and root[0]["ip"] == "203.0.113.5"


def test_benign_ip_not_flagged():
    report = core.analyze(SAMPLE_LOG.splitlines())
    assert "198.51.100.7" not in {i["ip"] for i in report["indicators"]}


def test_per_ip_stats():
    report = core.analyze(SAMPLE_LOG.splitlines())
    stats = report["per_ip"]["203.0.113.5"]
    assert stats["failed_password"] == 8
    assert stats["invalid_user"] == 4
    assert stats["root_login"] == 1
    assert "admin" in stats["users_tried"]


def test_threshold_adjusts_bruteforce():
    report = core.analyze(SAMPLE_LOG.splitlines(), bruteforce_threshold=10)
    bf = [i for i in report["indicators"] if i["type"] == "bruteforce_ssh"]
    assert bf == []


def test_cli_stdin(monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(SAMPLE_LOG))
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "203.0.113.5" in out
    assert "bruteforce_ssh" in out


def test_cli_json(tmp_path, capsys):
    import json
    logfile = tmp_path / "auth.log"
    logfile.write_text(SAMPLE_LOG)
    rc = main([str(logfile), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert "203.0.113.5" in data["per_ip"]

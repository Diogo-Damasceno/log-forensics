"""Núcleo do log-forensics: análise de logs de autenticação."""

from __future__ import annotations

import re
from collections import defaultdict

# Padrões típicos de /var/log/auth.log (syslog-style)
RE_FAILED = re.compile(r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_INVALID = re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_ROOT_LOGIN = re.compile(r"root login .*?(?:from |for )(?P<ip>\d+\.\d+\.\d+\.\d+)")


def parse_lines(lines) -> dict:
    """Processa linhas de log e acumula estatísticas por IP."""
    per_ip = defaultdict(lambda: {
        "failed_password": 0,
        "invalid_user": 0,
        "root_login": 0,
        "users_tried": set(),
    })

    for line in lines:
        line = line.rstrip("\n")

        m = RE_FAILED.search(line)
        if m:
            ip = m.group("ip")
            per_ip[ip]["failed_password"] += 1

        m = RE_INVALID.search(line)
        if m:
            ip = m.group("ip")
            user = m.group("user")
            per_ip[ip]["invalid_user"] += 1
            per_ip[ip]["users_tried"].add(user)

        m = RE_ROOT_LOGIN.search(line)
        if m:
            ip = m.group("ip")
            per_ip[ip]["root_login"] += 1

    return per_ip


def _serialize(per_ip: dict) -> dict:
    """Converte sets em listas ordenadas para saída serializável."""
    out = {}
    for ip, stats in per_ip.items():
        out[ip] = {
            "failed_password": stats["failed_password"],
            "invalid_user": stats["invalid_user"],
            "root_login": stats["root_login"],
            "users_tried": sorted(stats["users_tried"]),
        }
    return out


def analyze(lines, bruteforce_threshold: int = 5) -> dict:
    """Analisa linhas e gera relatório de indicadores por IP."""
    per_ip = parse_lines(lines)
    report = _serialize(per_ip)

    indicators = []
    for ip, stats in report.items():
        if stats["failed_password"] >= bruteforce_threshold:
            indicators.append({
                "type": "bruteforce_ssh",
                "ip": ip,
                "count": stats["failed_password"],
            })
        if stats["invalid_user"] >= 3:
            indicators.append({
                "type": "user_scanning",
                "ip": ip,
                "count": stats["invalid_user"],
            })
        if stats["root_login"] >= 1:
            indicators.append({
                "type": "root_login",
                "ip": ip,
                "count": stats["root_login"],
            })

    return {
        "per_ip": report,
        "indicators": indicators,
        "bruteforce_threshold": bruteforce_threshold,
    }

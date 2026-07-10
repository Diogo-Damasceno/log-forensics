"""Núcleo do log-forensics: análise de logs de autenticação."""

from __future__ import annotations

import re
from collections import defaultdict

# Padrões típicos de /var/log/auth.log (syslog-style)
RE_FAILED = re.compile(r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_INVALID = re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_ROOT_LOGIN = re.compile(r"root login .*?(?:from |for )(?P<ip>\d+\.\d+\.\d+\.\d+)")

# Limiares padrão para classificação de indicadores
DEFAULT_BRUTEFORCE_THRESHOLD = 5
USER_SCAN_THRESHOLD = 3

# Contadores mantidos por IP
STAT_FAILED = "failed_password"
STAT_INVALID = "invalid_user"
STAT_ROOT = "root_login"
STAT_USERS = "users_tried"


def parse_lines(lines) -> dict:
    """Processa linhas de log e acumula estatísticas por IP."""
    per_ip = defaultdict(lambda: {
        STAT_FAILED: 0,
        STAT_INVALID: 0,
        STAT_ROOT: 0,
        STAT_USERS: set(),
    })

    for line in lines:
        line = line.rstrip("\n")

        m = RE_FAILED.search(line)
        if m:
            per_ip[m.group("ip")][STAT_FAILED] += 1

        m = RE_INVALID.search(line)
        if m:
            ip = m.group("ip")
            per_ip[ip][STAT_INVALID] += 1
            per_ip[ip][STAT_USERS].add(m.group("user"))

        m = RE_ROOT_LOGIN.search(line)
        if m:
            per_ip[m.group("ip")][STAT_ROOT] += 1

    return per_ip


def _serialize(per_ip: dict) -> dict:
    """Converte sets em listas ordenadas para saída serializável."""
    out = {}
    for ip, stats in per_ip.items():
        out[ip] = {
            STAT_FAILED: stats[STAT_FAILED],
            STAT_INVALID: stats[STAT_INVALID],
            STAT_ROOT: stats[STAT_ROOT],
            STAT_USERS: sorted(stats[STAT_USERS]),
        }
    return out


def _build_indicators(report: dict, bruteforce_threshold: int) -> list:
    """Gera a lista de indicadores de ataque a partir do relatório por IP."""
    indicators = []
    for ip, stats in report.items():
        if stats[STAT_FAILED] >= bruteforce_threshold:
            indicators.append({
                "type": "bruteforce_ssh",
                "ip": ip,
                "count": stats[STAT_FAILED],
            })
        if stats[STAT_INVALID] >= USER_SCAN_THRESHOLD:
            indicators.append({
                "type": "user_scanning",
                "ip": ip,
                "count": stats[STAT_INVALID],
            })
        if stats[STAT_ROOT] >= 1:
            indicators.append({
                "type": "root_login",
                "ip": ip,
                "count": stats[STAT_ROOT],
            })
    return indicators


def analyze(lines, bruteforce_threshold: int = DEFAULT_BRUTEFORCE_THRESHOLD) -> dict:
    """Analisa linhas e gera relatório de indicadores por IP."""
    per_ip = parse_lines(lines)
    report = _serialize(per_ip)
    indicators = _build_indicators(report, bruteforce_threshold)
    return {
        "per_ip": report,
        "indicators": indicators,
        "bruteforce_threshold": bruteforce_threshold,
    }

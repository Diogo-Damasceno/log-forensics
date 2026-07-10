"""Interface de linha de comando do log-forensics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from logforensics.core import analyze


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logforensics",
        description="Detecta ataques em logs de autenticação (estilo auth.log).",
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        help="Arquivo de log. Se omitido, lê de stdin.",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=5,
        help="Limiar de falhas para considerar brute-force (padrao: 5).",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Emite o relatório em JSON em vez de texto legível.",
    )
    return parser


def _read_lines(logfile: str | None):
    if logfile:
        path = Path(logfile)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    return sys.stdin.readlines()


def render_text(report: dict) -> str:
    lines = []
    lines.append("=== log-forensics: relatorio ===")
    lines.append(f"Limiar de brute-force: {report['bruteforce_threshold']} falhas")
    lines.append("")
    if not report["per_ip"]:
        lines.append("Nenhuma entrada relevante encontrada.")
    for ip, stats in sorted(report["per_ip"].items()):
        lines.append(f"IP {ip}:")
        lines.append(f"  falhas de senha: {stats['failed_password']}")
        lines.append(f"  usuarios invalidos: {stats['invalid_user']}")
        lines.append(f"  root login: {stats['root_login']}")
        if stats["users_tried"]:
            lines.append(f"  usuarios testados: {', '.join(stats['users_tried'])}")
    lines.append("")
    lines.append("Indicadores de ataque:")
    if not report["indicators"]:
        lines.append("  (nenhum)")
    for ind in report["indicators"]:
        lines.append(f"  [{ind['type']}] {ind['ip']} (count={ind['count']})")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    lines = _read_lines(args.logfile)
    report = analyze(lines, bruteforce_threshold=args.threshold)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())

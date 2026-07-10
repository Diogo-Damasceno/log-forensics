# log-forensics

Ferramenta defensiva de linha de comando que analisa logs de autenticação
(estilo `/var/log/auth.log`) e detecta tentativas de ataque, agregando
estatísticas e indicadores **por endereço IP**.

## O que detecta

- **Brute-force SSH** — muitas ocorrências de `Failed password` de um mesmo IP.
- **Scanning de usuários** — tentativas contra múltiplos usuários inválidos.
- **Root login** — tentativas/aceites de login como `root`.

## ⚠️ Aviso ético

Esta é uma ferramenta **defensiva e educacional**, voltada à análise de logs
de sistemas **de sua propriedade ou nos quais você tenha autorização** para
investigar. Não a utilize para monitorar sistemas de terceiros sem
permissão. O autor não se responsabiliza por uso indevido.

## Requisitos

- Python 3.10+
- Apenas biblioteca padrão (sem dependências externas).

## Instalação

```bash
pip install -e .
```

## Uso

A partir de um arquivo de log:

```bash
logforensics /var/log/auth.log
```

Lendo de stdin (exemplo com um log de exemplo):

```bash
cat auth.log | logforensics
```

Com limiar personalizado de brute-force e saída JSON:

```bash
logforensics auth.log --threshold 10 --json
```

## Saída

- Modo texto: resumo por IP (falhas de senha, usuários inválidos, root
  login, usuários testados) e lista de indicadores de ataque.
- Modo `--json`: relatório estruturado com `per_ip`, `indicators` e o
  limiar utilizado.

## Testes

```bash
pytest
```

## Licença

MIT — Copyright (c) 2026 Diogo Damasceno.

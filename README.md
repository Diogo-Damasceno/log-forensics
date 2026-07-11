# log-forensics

Ferramenta defensiva de linha de comando que analisa logs de autenticação
(estilo `/var/log/auth.log`) e detecta tentativas de ataque, agregando
estatísticas e indicadores **por endereço IP**.

- **Brute-force SSH** — muitas ocorrências de `Failed password` de um mesmo IP.
- **Scanning de usuários** — tentativas contra múltiplos usuários inválidos.
- **Root login** — tentativas de login direto como root.

> ⚠️ Ferramenta **educacional e defensiva**. Use em logs de sistemas seus ou
> sob sua responsabilidade. Não aponte contra terceiros sem autorização.

## Instalação

Pré-requisitos: **Python 3.10+**.

```bash
git clone https://github.com/Diogo-Damasceno/log-forensics.git
cd log-forensics
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Após instalar, o comando do projeto fica disponível dentro do venv.
Para usar fora dele, crie um atalho:

```bash
mkdir -p ~/.local/bin
ln -sf "$(pwd)/.venv/bin/logforensics" ~/.local/bin/logforensics
```

> Dica: se `~/.local/bin` não estiver no teu `PATH`, rode
> `export PATH="$HOME/.local/bin:$PATH"` (e adicione ao `~/.bashrc`/`~/.zshrc`).


## Uso

```bash
# analisa um log de auth (SSH)
logforensics /var/log/auth.log

# lê da entrada padrão (útil com journalctl)
sudo journalctl -u sshd --no-pager | logforensics -
```

## Licença

MIT — veja `LICENSE`.

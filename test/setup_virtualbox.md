# Guia de configuração — VirtualBox + Windows Sandbox

## Topologia de rede

```
┌──────────────────────────────────────────────────────────────────┐
│  Windows Host (192.168.56.1)                                      │
│                                                                    │
│  ┌──────────────────────┐   ┌───────────────────────────────┐    │
│  │  VirtualBox VM        │   │  Windows Sandbox              │    │
│  │  Ubuntu 22.04 Server  │   │  (alvo da injeção de teclas)  │    │
│  │  192.168.56.101       │   │  Notepad em foco              │    │
│  │                       │   │                               │    │
│  │  c2_server.py         │   │  ← keystrokes chegam aqui     │    │
│  │  porta 9000 TLS       │   │                               │    │
│  └───────────┬───────────┘   └───────────────────────────────┘    │
│              │  Host-only Adapter (vboxnet0)                       │
│              │                                                      │
│  ┌───────────▼───────────────────────────────────────────────┐    │
│  │  pico_agent_sim.py                                         │    │
│  │  conecta em 192.168.56.101:9000 via TLS                    │    │
│  │  injeta teclas na janela em foco (pyautogui)               │    │
│  └───────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

---

## Passo 1 — VirtualBox: criar rede Host-Only

1. Abra o VirtualBox → **File** → **Host Network Manager**
2. Clique em **Create** (cria `vboxnet0`)
3. Configure:
   - **IPv4 Address:** `192.168.56.1`
   - **IPv4 Network Mask:** `255.255.255.0`
   - **DHCP Server:** habilitado
     - Server Address: `192.168.56.100`
     - Lower Bound: `192.168.56.101`
     - Upper Bound: `192.168.56.254`

---

## Passo 2 — VM Ubuntu: configuração

### Instalação rápida (Ubuntu Server 22.04 LTS)

Baixe: https://ubuntu.com/download/server

Crie a VM com:
- RAM: 1 GB mínimo (2 GB recomendado)
- Disco: 10 GB
- Rede Adaptador 1: **Host-only Adapter** → `vboxnet0`

> Dica: não precisa de NAT se só vai usar na rede interna de teste.

### Instalar dependências na VM

```bash
sudo apt update && sudo apt install -y python3 python3-pip openssl

# Confirme que Python ≥ 3.11 (para ssl.TLSVersion.TLSv1_3)
python3 --version
```

### Descobrir IP da VM

```bash
ip addr show | grep inet
# Anote o 192.168.56.x — use em RUNNER_HOST e em gen_certs.sh (SRV_IP)
```

---

## Passo 3 — Gerar certificados TLS (na VM)

```bash
# Copie gen_certs.sh para a VM (via shared folder ou scp)
# ANTES de rodar, edite SRV_IP para o IP da sua VM:
nano gen_certs.sh
# Altere: SRV_IP="192.168.56.101"

chmod +x gen_certs.sh
./gen_certs.sh
```

Copie `ca.pem` para o Windows Host:
```bash
# Opção 1: shared folder do VirtualBox
cp ca.pem /media/sf_shared/

# Opção 2: python HTTP server temporário
python3 -m http.server 8080
# No host: abra http://192.168.56.101:8080/ca.pem
```

---

## Passo 4 — Iniciar o servidor C2 na VM

```bash
cd /home/usuario/pico_c2/server

export RUNNER_TOKEN="testtoken_troque_por_algo_longo"
export RUNNER_HMAC_SECRET="testhmac_troque_por_algo_longo"
export RUNNER_CERT="../server.pem"
export RUNNER_KEY="../server.key"

python3 c2_server.py
```

Saída esperada:
```
2024-01-01T12:00:00 [INFO] listening on 0.0.0.0:9000 (TLS 1.3)
```

### Firewall na VM (se necessário)
```bash
sudo ufw allow 9000/tcp
```

---

## Passo 5 — Windows Host: instalar dependências

Abra o PowerShell como administrador:

```powershell
# Python 3.11+ deve estar instalado
# https://www.python.org/downloads/

pip install pyautogui
```

---

## Passo 6 — Windows Sandbox: preparar o alvo

O Windows Sandbox é reiniciado a cada abertura — não precisa instalar nada.

1. Procure **Windows Sandbox** no menu Iniciar
   - Se não aparecer: **Painel de Controle** → **Ativar ou desativar recursos do Windows**
   - → marque **Windows Sandbox** → OK → reinicie

2. Abra o Sandbox
3. Dentro do Sandbox, abra o **Notepad** e deixe-o maximizado em foco

> O pyautogui injeta nas janelas do **host**, não dentro do Sandbox.
> O Sandbox serve como ambiente de demonstração visual separado.
> Para injetar DENTRO do Sandbox seria necessário rodar o simulador dentro dele.

### Alternativa: usar o próprio host como alvo
Abra o Notepad no Windows Host, deixe em foco, e rode o simulador.
É a forma mais simples para ver a injeção de teclas funcionando.

---

## Passo 7 — Iniciar o simulador no Windows Host

Abra um PowerShell ou CMD:

```powershell
set RUNNER_HOST=192.168.56.101
set RUNNER_PORT=9000
set RUNNER_TOKEN=testtoken_troque_por_algo_longo
set RUNNER_HMAC_SECRET=testhmac_troque_por_algo_longo
set RUNNER_CA_CERT=C:\caminho\para\ca.pem

# OU em modo lab (sem verificar cert — mais simples para teste):
set RUNNER_LAB_MODE=1

python pico_agent_sim.py
```

Saída esperada:
```
[INFO] simulador do Pico W iniciado → 192.168.56.101:9000
[INFO] [T1] TLS handshake OK  proto=TLSv1.3  cipher=TLS_AES_256_GCM_SHA384
[INFO] [T1] enviando auth…
[INFO] [T1] ✓ autenticado
```

---

## Passo 8 — Executar a suite de testes

```powershell
set RUNNER_HOST=192.168.56.101
set RUNNER_LAB_MODE=1
set RUNNER_TOKEN=testtoken_troque_por_algo_longo
set RUNNER_HMAC_SECRET=testhmac_troque_por_algo_longo

python run_tests.py
```

---

## Troubleshooting

| Sintoma | Causa provável | Solução |
|---|---|---|
| `Connection refused` no host | VM não iniciada ou firewall | Verifique `ufw`, `python3 c2_server.py` rodando |
| `SSL: CERTIFICATE_VERIFY_FAILED` | IP do cert ≠ IP da VM | Regerar certs com `SRV_IP` correto |
| Teclas não aparecem no Notepad | Notepad não está em foco | Clique no Notepad antes de rodar |
| `pyautogui.FailSafeException` | Mouse foi para canto superior esquerdo | Mova o mouse para o centro da tela |
| Auth falha com `testtoken` | Token diferente no servidor e simulador | Confirme que as vars de ambiente são iguais nos dois |
| Rate limit em T4 muito cedo | Clock da VM desincronizado | `timedatectl status` na VM |

---

## Layout dos terminais recomendado

```
┌────────────────────┬────────────────────┐
│  Terminal 1 (VM)   │  Terminal 3 (host) │
│  c2_server.py      │  run_tests.py      │
│  logs do servidor  │  resultado dos     │
│                    │  testes            │
├────────────────────┼────────────────────┤
│  Terminal 2 (host) │  Notepad           │
│  pico_agent_sim.py │  (alvo em foco)    │
│  logs do simulador │                    │
└────────────────────┴────────────────────┘
```

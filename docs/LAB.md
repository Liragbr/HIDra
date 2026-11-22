# Laboratório, dependências e build

## Ambiente

Linux com Python 3.11–3.13, OpenSSL, Git, compilador C/C++ e headers OpenSSL para os
testes nativos. Exemplo de instalação em Ubuntu/Debian:

```bash
sudo apt-get install build-essential libssl-dev openssl git curl xz-utils
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

As versões efetivamente executadas estão em [VALIDATION.md](VALIDATION.md).
`requirements-dev.txt` fixa também dependências transitivas das ferramentas; não
representa dependências do servidor em runtime. O runtime usa somente stdlib.

## Preparação das fontes embarcadas

Use diretórios fora do repositório ou sob `build/` (ignorado por Git):

```bash
mkdir -p build/deps
git clone https://github.com/raspberrypi/pico-sdk.git build/deps/pico-sdk
git -C build/deps/pico-sdk checkout --detach 079c6f39023649b154152db30f1d781e884879bc
git -C build/deps/pico-sdk submodule update --init lib/cyw43-driver lib/lwip lib/tinyusb

git clone https://github.com/Mbed-TLS/mbedtls.git build/deps/mbedtls
git -C build/deps/mbedtls checkout --detach 82e69999f91126589a28b70dd75b69fbcabe2711
export PICO_SDK_PATH="$PWD/build/deps/pico-sdk"
export PICO_MBEDTLS_PATH="$PWD/build/deps/mbedtls"
python scripts/check_dependencies.py
```

O script verifica commits e alterações locais. Bluetooth/BTstack não é usado;
um aviso do SDK sobre esse submódulo ausente não é evidência de falha de Wi-Fi.
A cópia de mbedTLS que pertence ao SDK não é utilizada.

Instale Arm GNU Toolchain 14.3.rel1 (Linux x86_64) usando a URL e SHA-256 de
[dependencies.lock.json](../dependencies.lock.json), como no workflow. O PATH deve
conter `arm-none-eabi-gcc`, `arm-none-eabi-g++`, `arm-none-eabi-size` e ferramentas
associadas. O checksum fixa o arquivo obtido por HTTPS; não foi feita validação de
assinatura GPG do distribuidor. CMake 4.4.5 e Ninja 1.13.2 estão no lock Python.

O SDK obtém picotool para gerar UF2. A versão solicitada vem do SDK fixado; confira
os logs de configure. Bootstrap precisa de rede para fontes e ferramentas; os
testes de protocolo não usam a Internet.

## Certificados e configuração

Crie uma CA exclusiva para esse laboratório. Não reutilize uma CA corporativa:

```bash
SRV_IP=192.168.1.100 SRV_DNS=hidra.lab bash gen_certs.sh lab-certs
cp lab-certs/ca_cert.h firmware/ca_cert.h
cp firmware/agent_config.example.h firmware/agent_config.local.h
```

O diretório de saída precisa ser novo. O gerador usa `umask 077`, mantém CA e chave
servidora privadas e remove CSR/extensões temporárias. Certificado servidor vale
90 dias; isso não substitui renovação e relógio confiável no firmware.

Edite o header **local**: SSID/senha, endereço IPv4 numérico `C2_ADDRESS`, identidade
DNS ou IP `C2_HOST` que corresponde ao SAN, porta, token e HMAC. Não há resolução DNS
no firmware: transporte e identidade são campos separados. Essa redução explícita
elimina callbacks DNS com vida útil ambígua durante cancelamento.

Gere token e HMAC independentemente com `openssl rand -hex 32`. Configure os mesmos
valores nas variáveis `RUNNER_TOKEN` e `RUNNER_HMAC_SECRET` do servidor, em um ambiente
local controlado. Não coloque segredos em comandos registrados por histórico,
issues, commits, screenshots ou logs de CI. O formato hexadecimal evita ambiguidades
de escaping no header C.

Distribua somente a CA pública por um canal autenticado. Não sirva o diretório das
chaves com um servidor HTTP. `agent_config.local.h`, certificados, chaves e artefatos
compilados estão excluídos do versionamento; `scripts/check_security.py` verifica
que não foram adicionados aos arquivos rastreados.

## Compilação por placa

```bash
bash scripts/build_firmware.sh pico_w
bash scripts/build_firmware.sh pico2_w
```

Cada chamada usa diretório próprio. CMake seleciona placa **antes** de inicializar
o SDK, exige o SDK 2.3.1 e mbedTLS 3.6.8, e falha se configuração/CA estiverem ausentes.
Código do projeto é compilado com `-Wall -Wextra -Werror -Wconversion -Wshadow`.
Não há sockets POSIX no firmware: BIO mbedTLS usa lwIP raw, com polling no Core 0.
TinyUSB pertence exclusivamente ao Core 1; USB stdio é desligado, UART stdio ligado.

Core 0 reserva 24 KiB de stack no fim da RAM principal, fora do heap. Core 1 reserva
4 KiB na região scratch X. CMake ajusta as regiões de linker para cada MCU; só aumentar
`PICO_STACK_SIZE` ultrapassaria a scratch Y padrão de 4 KiB. A reserva não é uma
medição do pico de stack. Heap TLS e margem real precisam de teste físico.

Para apenas reproduzir builds de CI, em checkout sem configuração local:

```bash
python scripts/provision_build_fixture.py
```

Isso cria credenciais públicas de compilação e certificados descartáveis.
**Não flashear imagens produzidas com esse fixture.** UF2/ELF não são publicados no CI.

## Testes isolados

```bash
python -W error::ResourceWarning test/run_tests.py
bash test/run_native.sh
bash test/run_mbedtls_host.sh
python -m compileall -q hidra server test scripts
ruff check hidra server test scripts
bandit -r hidra server test/pico_agent_sim.py -q
pip-audit --strict --disable-pip --no-deps -r requirements-dev.txt
```

`run_tests.py` falha se não encontrar testes e retorna não zero para qualquer falha.
A suíte cria os próprios processos/threads, portas e certificados; não precisa de
servidor ou GUI já abertos. O teste mbedTLS usa BIO POSIX de teste e o **mesmo header
de configuração criptográfica**, mais o codec C do firmware. Não testa CYW43/lwIP.

Em ambientes sob ptrace, LeakSanitizer pode ser incompatível. Nesse caso, registre
LSan como NOT TESTED e execute apenas ASan/UBSan com:

```bash
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 bash test/run_native.sh
```

Não converta o erro de LSan em PASS de detecção de vazamentos. O workflow mantém
LSan habilitado por padrão.

## Teste físico pendente

Somente depois de revisar os limites de [SECURITY.md](SECURITY.md), use uma placa e
um computador próprios, rede dedicada e editor vazio aberto manualmente. Não use
shell, produção ou host corporativo. Teste enumeração, press/release, ASCII/layout,
unplug, suspend/resume, Wi-Fi indisponível, certificado inválido, falta de memória,
limites de fila, queda de rede e execução prolongada. Registre placa/revisão,
firmware SHA, configuração sem segredos, captura UART sanitizada e critério objetivo.

Nenhum desses procedimentos foi executado fisicamente nesta auditoria. O RP2350
não ganha secure boot nem proteção de flash por simplesmente compilar este projeto.

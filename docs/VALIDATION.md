# Matriz de validação

Execução local em 2026-11-22, Linux x86_64, Python 3.12.14, OpenSSL 3.5.7,
GCC host 14.2.0, Arm GNU 14.3.rel1 / GCC 14.3.1, CMake 4.4.5, Ninja 1.13.2.
Fontes: pico-sdk 2.3.1 + mbedTLS externo 3.6.8, commits de
[dependencies.lock.json](../dependencies.lock.json).

PASS exige execução e critério objetivo satisfeito. FAIL significa tentativa que
não satisfez o critério. NOT TESTED não implica aprovação. Os logs abaixo são de
host; não há resultados de placa física. Valores de build variam com certificado,
provisionamento e timestamp: reprodução do procedimento não promete binários
idênticos byte a byte sem controlar também essas entradas.

| Verificação | Resultado local | Critério / evidência |
|---|---|---|
| Suíte Python + codec C | **PASS — 49 testes** | `python3 -W error::ResourceWarning test/run_tests.py`, saída zero e `OK`; [log](../evidence/python-tests.log) |
| Auth válida/inválida, action/tipos indevidos | PASS | Auth correta aceita; demais rejeitadas e socket fechado |
| HMAC errado, corpo adulterado, direção/sid incorretos | PASS | Sem despacho no sink; rejeição terminal |
| Replay na sessão, entre sessões e reordenação | PASS | Sequência exata e sid novo; captura anterior rejeitada |
| JSON inválido, duplicado, aninhado, truncado e excessivo | PASS | Exceção controlada/rejeição; sem sucesso parcial de parsing |
| Fragmentação byte a byte e frames coalescidos | PASS | Recuperação dos objetos exatos, em ordem |
| TLS 1.3 Python/OpenSSL e rejeição TLS 1.2 | PASS | Versão negociada exata, protocolo antigo recusado |
| CA, hostname e expiração no cliente Python | PASS | Falha SSL de verificação; expiração verifica código 10 |
| TLS 1.3 com configuração mbedTLS real + codec C | **PASS — 4 testes** | [log](../evidence/mbedtls-host.log); sucesso auth/exit, falhas X509 `-0x2700` para CA/hostname/expiração |
| Handshake parado, auth timeout, response timeout | PASS | Prazo expira, segundo cliente progride, sessão fica fechada |
| Limite de conexões e admissão | PASS | Slot excedente fechado, serviço recupera após liberar slot |
| Rate limit e janela exata | PASS | 30 aceitos / 5 rejeitados em 35; expira em 60 s; C testado em boot e wrap |
| Recuperação/backoff do simulador | PASS | Falhas injetadas em conexão/EOF geram espera; posterior conexão autentica; rate preservado |
| CLI/keepalive: transações concorrentes | PASS | 12 requisições simultâneas recebem o pong correspondente sem sobreposição de I/O |
| Parser Ducky e script completo no simulador | PASS | Lista de eventos exatamente igual; servidor encerra; rejeição interrompe script |
| Certificados sem sobrescrita e permissões | PASS | Segunda geração falha; chave original preservada; nenhum bit de acesso para grupo/outros |
| Logs sem credenciais/payload | PASS | Asserções sobre logs de falha; conteúdo não incluído |
| ASan + UBSan nativos | PASS | [log](../evidence/native-sanitizers.log); 50.000 casos de parser e todas as truncagens do frame de referência |
| Fila nativa | PASS | Capacidade útil 63, cancelamento, idle/busy; 100.000 registros FIFO entre duas threads com campos exatos |
| LeakSanitizer local | **NOT TESTED** | Tentativa falhou por ptrace; [diagnóstico](../evidence/lsan-unavailable.log). ASan/UBSan foram executados com `detect_leaks=0` |
| Sintaxe Python, Ruff, Bandit, sintaxe shell | PASS | [log estático](../evidence/static-analysis.log); comandos de [LAB.md](LAB.md) |
| GCC warnings/análise do codec e fila | PASS | `-Wall -Wextra -Werror -Wconversion -Wshadow -fanalyzer -c` |
| Dependências Python | PASS | `pip-audit --disable-pip --no-deps -r requirements-dev.txt`; [log](../evidence/dependency-audit.log). Resultado é consulta de advisories, não garantia absoluta |
| Build Pico W / RP2040, verificação TLS ligada | **PASS — ELF e UF2** | [log](../evidence/build-pico_w.log), saída zero; nenhuma gravação de placa |
| Build Pico 2 W / RP2350 Arm, verificação TLS ligada | **PASS — ELF e UF2** | [log](../evidence/build-pico2_w.log), saída zero; nenhum teste RISC-V |
| Build com bypass TLS | NOT TESTED | Não necessário à validação principal; não alegado como aprovado |
| GitHub Actions remoto | NOT TESTED | Será atualizado com run/commit verificáveis após publicar a branch |
| Enumeração, layout, press/release no host USB | **NOT TESTED** | Hardware/host físico indisponíveis |
| CYW43, lwIP raw e recuperação Wi-Fi em placa | **NOT TESTED** | BIO POSIX do teste mbedTLS não emula rádio/lwIP |
| Heap/stack máximos, energia, latência e soak físico | **NOT TESTED** | Tamanho de ELF/UF2 não mede uso máximo de memória nem desempenho |
| Hora civil, entropia e canais laterais físicos | **NOT TESTED** | Limitações de [SECURITY.md](SECURITY.md) |

## Tamanho estático observado

`arm-none-eabi-size`, exatamente como registrado nos logs finais locais:

| Alvo | text (bytes) | data (bytes) | bss (bytes) |
|---|---:|---:|---:|
| pico_w | 512512 | 0 | 73820 |
| pico2_w | 487604 | 0 | 73180 |

Esses números descrevem seções do ELF com os fixtures de build. Não são benchmark,
heap máximo, stack máxima ou margem operacional validada. Reservas de stack e o
mapa de linker devem ser examinados separadamente de alocações dinâmicas TLS.

## Cobertura e lacunas

Os testes C exercitam o parser/codec/fila de produção, não uma reimplementação deles.
O adaptador criptográfico de vetores usa OpenSSL; a integração adicional usa mbedTLS
3.6.8 real. O stress da fila usa mutex pthread para representar a região crítica;
não comprova o comportamento de IRQs, spinlocks e USB nos dois núcleos físicos.
O corpus de 50.000 casos é determinístico e não constitui fuzzing exaustivo.

A fila/HID em firmware tem prazo total, cancelamento e tratamento de endpoint
indisponível no código; confirmação temporal em placa permanece NOT TESTED. O
simulador não executa shell, não importa pyautogui e não envia teclas a qualquer host.

## Evidência da base

Na base anterior, `test/run_tests.py` falhava com SyntaxError antes de executar;
entradas `[]` e `body:42` no servidor causavam TypeError/AttributeError. Essas falhas
foram reproduzidas antes das alterações, conforme [AUDIT_INITIAL.md](AUDIT_INITIAL.md).
Elas são histórico de FAIL, não resultados da suíte corrigida.

# Modelo de ameaças e limitações

## Fronteiras e pressupostos

Servidor, operador e host de build são confiáveis. A rede pode observar, modificar,
repetir e interromper tráfego. Agentes sem o token/HMAC e peers enviando dados
malformados são tratados como não confiáveis. Testes usam loopback; não houve ação
sobre máquinas de terceiros, ambiente corporativo ou hardware físico.

O projeto reduz exposição a MITM com TLS 1.3, CA local e hostname. HMAC vincula
corpo, direção, sessão e sequência. Não substitui TLS nem fornece autorização por
comando. O servidor que possui as credenciais pode enviar qualquer comando HID
suportado. Comprometimento do servidor está fora da proteção do protocolo.

## Garantias limitadas

- Nenhuma credencial padrão funcional: configuração local é ignorada por Git;
  token/HMAC são obrigatórios e distintos. Recomenda-se gerar 32 bytes aleatórios
  para cada um, codificados em 64 caracteres hex. Comprimento não mede entropia.
- Comparação de token e HMAC sem saída antecipada dependente do conteúdo no caminho
  de tamanho válido. Não foi realizada análise de tempo em silício/assembly.
- JSON limitado antes de uso, assinaturas antes de despacho; duplicatas, truncamento,
  números fora do contrato, Unicode/NUL, mensagens grandes e replay são rejeitados.
- Servidor: oito workers, admissão global 60/min, handshake fora do accept,
  prazos para autenticação e respostas. Isso limita recursos; não elimina DoS.
- Fila entre núcleos protegida por seção crítica do SDK. Não é apresentada como
  lock-free. Falhas de USB/rede cancelam pendências; consumer tenta liberar teclas
  quando o endpoint voltar a estar disponível. Sem USB, liberação física não pode
  ser garantida.
- Logs não incluem token, HMAC, assinaturas nem conteúdo de comandos. Exceções de
  TLS registram apenas o código/reason da biblioteca, não dados enviados pelo peer.

## Riscos residuais

| Risco | Impacto / condição | Estado |
|---|---|---|
| Segredos em flash/UF2 | Posse física ou acesso ao artefato pode revelar rede, token e HMAC | Sem secure boot, criptografia de flash ou proteção contra extração |
| Hora civil no firmware | Build epoch + uptime reinicia a cada boot; firmware antigo pode aceitar certificado expirado na hora real | **Limitação de segurança aberta**; não alegar validação temporal confiável no hardware |
| Servidor/CA comprometidos | Controle dos comandos ou emissão de identidade confiável | Fora da proteção; laboratório isolado e CA dedicada |
| Credenciais compartilhadas | Um dispositivo comprometido afeta outros com o mesmo segredo | Provisionar por laboratório/dispositivo; rotação requer rebuild |
| Efeito parcial de HID | Falha após algumas teclas não permite rollback; ACK não comprova execução | Requer host próprio, foco controlado e validação manual |
| DoS de rede | Limite global pode bloquear clientes legítimos; Wi-Fi/TCP podem ser interrompidos | Recuperação limitada, sem promessa de disponibilidade sob ataque |
| Recursos do RP2040 | Pico de heap/stack, latência, fragmentação e coexistência USB/Wi-Fi não medidos | Build não substitui soak test físico |
| Entropia e canais laterais | Teste host usa getrandom; firmware usa pico_rand pelo adaptador do SDK | Sem caracterização física de entropia, energia ou tempo |
| Dependências embarcadas | Revisão dos avisos citados não é uma varredura exaustiva de toda a cadeia | Versões fixadas; revisão periódica necessária |

`AGENT_LAB_MODE=ON` (firmware) e `RUNNER_LAB_MODE=1` (simulador) desabilitam
verificação de identidade. São explícitos e desligados por padrão. Mantêm TLS e HMAC,
mas **não são configuração segura contra MITM**. Não usar como solução para CA/SAN
incorretos. Não foi validado o build de bypass; a matriz principal usa verificação.

## Revisão de dependências em 2026-11-22

O pico-sdk 2.3.1 aponta para mbedTLS 3.6.6. O projeto exige uma cópia externa de
**mbedTLS 3.6.8**, commit fixado, após revisão dos avisos oficiais abaixo.
A atualização foi seguida de rebuild por placa e testes TLS reais em host.

| Aviso oficial | Aplicabilidade ao HIDra e decisão |
|---|---|
| [CVE-2026-93843: vazamento no setup TLS 1.3](https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2026-11-tls13-transform-resource-leak/) | Relevante a falhas de alocação/backend em TLS 1.3. Resolvido upstream em 3.6.8; não foi reproduzido um esgotamento no dispositivo. |
| [CVE-2026-115490: confusão de versão TLS](https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2026-11-tls-version-confusion/) | O caminho exige TLS 1.2+1.3; HIDra compila e negocia somente 1.3. Atualização aplicada mesmo assim. |
| [CVE-2026-90470: tipo de SAN](https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2026-11-wildcard-type-confusion/) | Uso documentado é DNS/IP, não URI. Corrigido upstream em 3.6.8. |
| [CVE-2026-115492: tabelas AES em flash](https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2026-11-aes-rom-tables/) | `MBEDTLS_AES_ROM_TABLES` permanece desabilitado; isto não demonstra ausência de outros canais laterais. |
| [CVE-2026-73096: early data](https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2026-07-tls13-early-data-integrity-failure-key-change/) | Não há servidor mbedTLS nem early data habilitado no firmware; 3.6.8 também inclui a correção. |

`pip-audit` cobre a lista de ferramentas Python fixadas; runtime Python não tem
dependências externas. Não cobre OpenSSL do sistema, TinyUSB, lwIP ou CYW43. O lock
valida identidade de fontes, não ausência de vulnerabilidades. Dependabot acompanha
pip/Actions; atualizar SDK/mbedTLS exige revisão do lock e repetição dos testes.

## Falhas e divulgação

Não publique credenciais, chaves ou binários provisionados em issues. Ao relatar um
bug, inclua commit, placa, toolchain, configuração sem segredos e reprodução mínima
com simulator/loopback. Para falhas que possam afetar terceiros, utilize um canal
privado do mantenedor antes de publicar detalhes de exploração.

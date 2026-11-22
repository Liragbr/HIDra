# Auditoria inicial — antes das alterações

Base: `59ca97f7209bab3c7197dd069edd541725b3e83b`, examinada em 2026-11-22.
Todos os 16 arquivos versionados foram lidos: README, gitignore, oito arquivos
de firmware, gerador de certificados, servidor, exemplo e três arquivos de teste.
Não há dependências vendorizadas além do parser jsmn. Hardware não disponível.
Severidades são qualitativas, considerando laboratório próprio com servidor de
comandos confiável; não representam pontuações CVSS nem exploração remota demonstrada.

| ID | Severidade / classe | Evidência inicial e impacto |
|---|---|---|
| A01 | Alta / bug comprovado | `main.c:proto_send` insere JSON sem escapar dentro de string JSON. Reprodução equivalente com `json.loads` falha. `json_get_str` copia escapes literalmente; HMAC do servidor é calculado sobre bytes diferentes. Protocolo não interoperável. |
| A02 | Alta / disponibilidade comprovada | `Proto.recv` aceita `[]` e `body:42` até provocar TypeError/AttributeError. Reprodução local, sem rede. Ausência de validação estrutural também atinge token, assinatura e corpo. |
| A03 | Alta / risco arquitetural | Handshake bloqueante no accept, autenticação/leitura sem prazo, threads ilimitadas e sockets sem fechamento garantido permitem esgotamento de recursos. Não realizado teste de carga externo. |
| A04 | Alta / risco arquitetural | HMAC opcional, sem nonce, sequência ou separação de direção. Replay da aplicação não prevenido. TLS protege os registros no transporte; isto não demonstra replay de registros TLS. |
| A05 | Alta / integração incompatível | CMake seleciona placa após SDK init; somente lê SDK do ambiente. Faltam `lwipopts.h`, `tusb_config.h`; `mbedtls_net_*` pressupõe sockets POSIX, não disponibilizados pelo modo lwIP NO_SYS. Config TLS 1.3 não configura PSA, PEM/base64 e RSA-PSS adequadamente. Build ainda não executado nesta etapa. |
| A06 | Alta / disponibilidade comprovada por código | Produtor gira sem prazo quando ring enche, inclusive USB não montado. Consumidor bloqueia `tud_task` com sleep. Dados pendentes sobrevivem desconexão de rede. Não demonstrado no hardware. |
| A07 | Média / sincronização a validar | Índices volatile e barreiras incompletas não expressam acquire/release no modelo C. Race/corrupção física são hipóteses, não resultados medidos. GET_REPORT retorna comprimento sem inicializar buffer. |
| A08 | Média / bug comprovado por código | `now - 60000` unsigned faz underflow no primeiro minuto, removendo timestamps válidos. Comparação absoluta de microssegundos falha no wrap. |
| A09 | Média / bug comprovado por código | CLI envia enquanto handler envia ping e recebe respostas; falta exclusão de transações. Registry compartilhado sem lock. Script ignora rejeição e não encerra servidor conforme ajuda. |
| A10 | Média / validação de comando | Parser não desfaz escapes, busca campos aninhados/duplicados, usa assinatura possivelmente não inicializada; atoi permite entradas ambíguas; combo ignora tokens e sobrescreve tecla. Limites 64 KiB Python / 2 KiB firmware divergentes. |
| A11 | Alta / evidência inválida | `test/run_tests.py:279` tem SyntaxError (`**` num set). T2–T4 enviam comandos agente→servidor sem roteamento existente. HMAC das respostas não verificado. T4-e aprova incondicionalmente. `crit` indefinido no caminho sem token. |
| A12 | Média / isolamento | Importar simulador exige pyautogui; teste pode digitar na janela do host. Não há backend sem efeitos nem asserções sobre eventos. Logs incluem conteúdo de comandos. |
| A13 | Média / configuração | Gerador sobrescreve CA/chaves, não fixa umask restritivo, instruções apontam para diretório inexistente. Guia sugere servir diretório contendo chave privada por HTTP. Credenciais devem sair do header versionado. |
| A14 | Média / honestidade técnica | README afirma Pico W testado, memória TLS <60 KiB e secure boot/criptografia sem evidências. Exemplo de log não identificado como ilustrativo. Sem CI ou matriz de resultados. |
| A15 | Média / recuperação | Firmware não reconecta Wi-Fi depois da falha inicial; backoff não reinicia, pode exceder teto após jitter. Simulador pode reconectar imediatamente após EOF e recria rate limiter por sessão. |

## Execuções iniciais

Python 3.12.14: AST de servidor e simulador PASS; runner FAIL por SyntaxError.
Fake socket com `[]` produz TypeError; corpo numérico produz AttributeError.
Serialização equivalente à C produz JSONDecodeError. Nenhum payload HID executado.
Toolchain Arm, CMake e SDK não estavam no PATH inicial; builds ainda NOT TESTED.

## Plano técnico

Versionar o protocolo com desafios de ambos os peers, HMAC obrigatório e sequências;
rejeitar protocolo legado, documentando a quebra. Compartilhar implementação Python
entre servidor e simulador, e validar implementação C com vetores cruzados.
Preservar Core 0 rede / Core 1 USB e fila limitada, acrescentando sincronização,
prazos e descarte seguro. Compilar cada placa separadamente se possível. Registrar
resultados reais, inclusive bloqueios e itens dependentes de hardware.

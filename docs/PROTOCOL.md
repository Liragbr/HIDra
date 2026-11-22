# Protocolo HIDra v2

## Transporte e estados

TCP/TLS 1.3. Uma mensagem ASCII por linha LF, no máximo **2048 bytes antes do LF**.
Campos JSON são únicos; objeto plano, no máximo oito campos, nomes até 16 caracteres.
Strings não admitem NUL nem caracteres fora de ASCII. Inteiros são não negativos,
até 2147483647; floats, null, NaN, arrays e objetos aninhados são rejeitados.
Espaço JSON é permitido; CR dentro de string precisa estar escapado. Texto HID
suporta somente ASCII imprimível, LF e TAB, com layout US-QWERTY.

1. TLS validado: servidor envia `{"challenge":"<64 hex minúsculos>"}`.
2. Agente gera seu próprio nonce e envia `{"nonce":"<64 hex minúsculos>"}`.
3. Ambos calculam `sid = SHA256(ASCII("HIDra/2\n" + challenge + "\n" + nonce))`, em hex minúsculo.
4. Agente envia envelope com sequência 1: `{"action":"auth","token":"..."}`.
5. Servidor responde com sequência 1: `{"ok":true,"action":"ok"}` ou rejeita e fecha.
6. Servidor inicia comandos na sequência 2; agente responde a partir da sequência 2.

Os dois prefácios são transportados dentro de TLS. Não são comandos e não aceitam
campos extras. Cada ponta contribui com aleatoriedade fresca para evitar reutilização
da identidade da sessão por repetição do prefácio da outra ponta.

## Envelope autenticado

```json
{"v":2,"sid":"<64 hex>","seq":1,"body":"{\"action\":\"ping\"}","sig":"<64 hex>"}
```

`body` é uma **string JSON**, cujo conteúdo decodificado é outro objeto JSON.
HMAC-SHA256 usa os bytes ASCII exatos do corpo decodificado, sem reserialização:

```text
HIDra/2\n<direção>\n<sid>\n<seq decimal>\n<body>
```

Neste bloco `\n` representa um byte LF. Direções: `s2a` servidor→agente e `a2s`
agente→servidor. Não existe LF adicional no fim da entrada HMAC.
`seq` tem contadores independentes por direção, começa em 1 e precisa ser exatamente
a próxima sequência esperada. Nenhum salto, repetição, wrap ou retomada de sessão é
aceito. `body` tem no máximo **768 bytes decodificados**. Assinatura precisa ter
exatamente 64 caracteres hex minúsculos e é comparada em tempo constante no caminho
válido de comprimento fixo. Token usa `hmac.compare_digest` no servidor.

Falha de framing, EOF parcial, assinatura, sessão, sequência ou estrutura JSON é
terminal; não há tentativa de ressincronização. A aplicação não tenta reenviar
comandos cujo resultado ficou incerto. TLS não usa early data/0-RTT neste projeto.

## Comandos e respostas

| Direção | Corpo | Critério |
|---|---|---|
| Agente→servidor, somente autenticação | `{"action":"auth","token":"..."}` | Token e HMAC obrigatórios, independentes, 32–127 caracteres ASCII sem espaços |
| Servidor→agente | `{"action":"ping"}` | Resposta `{"ok":true,"action":"pong"}` |
| Servidor→agente | `{"action":"type","text":"abc"}` | 1–256 caracteres suportados |
| Servidor→agente | `{"action":"key","keys":"CTRL a"}` | Até 63 caracteres; uma tecla normal e modificadores válidos, sem tokens repetidos |
| Servidor→agente | `{"action":"delay","text":"100"}` | Decimal canônico entre 0 e 5000, sem sinal/zeros iniciais |
| Servidor→agente | `{"action":"exit"}` | Cancela fila, responde e encerra sem reconectar |
| Servidor→agente | `{"action":"terminate"}` | Cancela fila e solicita reboot no firmware; encerra o simulador |

Modificadores: CTRL, CONTROL, SHIFT, ALT, WIN, GUI. Teclas: ENTER, ESC, TAB, SPACE,
DEL, BACKSPACE, HOME, END, PGUP, PGDN, UP, DOWN, LEFT, RIGHT, F1–F12 e uma letra/dígito.
No firmware, letra maiúscula implica Shift; o parser Ducky normaliza letras isoladas
para minúsculas. Combinações com mais de uma tecla normal são rejeitadas.

Para type/key/delay, sucesso é `{"ok":true}`; rejeição é `{"ok":false,"error":"..."}`.
Comando semanticamente inválido, mas com envelope válido, recebe rejeição e pode ser
seguido de outro comando. Não há canal arbitrário de execução de programas.

Rate limit do agente: **30 comandos type/key/delay por janela móvel de 60 s**.
Comandos inválidos não contam. A tentativa válida conta mesmo se USB/fila falhar.
O estado persiste entre reconexões do processo/dispositivo. Reiniciar remove o estado.
Ping/exit/terminate não contam. Servidor limita novas conexões globalmente a 60/min,
com no máximo oito workers simultâneos por padrão, incluindo handshakes.

## Semântica de aceitação e encerramento

O firmware confirma quando a fila e as esperas de liberação/delay terminam e o
endpoint está pronto novamente. Não há confirmação da aplicação no host USB. Delay entra na mesma fila e mantém a ordem. O simulador confirma registro em
memória e **não dorme para emular tempo de USB**. Não é um emulador de temporização.

Ao receber exit, qualquer pendência é descartada. O servidor espera a resposta de
cada comando antes do próximo; o firmware só confirma após drenar sua fila, evitando
que o exit de um script bem-sucedido cancele o comando anterior. Isso não é evidência
de que o sistema operacional recebeu ou interpretou corretamente as teclas.

Cada comando tem um prazo total de **15 s**, abrangendo enfileiramento e consumo.
Falha parcial não pode desfazer teclas já emitidas e cancela o restante. Falhas de
USB ou EOF detectado pela rede interrompem a espera. Leitura/escrita/handshake do
firmware têm prazo de 20 s; servidor e simulador usam 20 s por operação/frame. O
prazo de frame não reinicia a cada byte. São limites configurados, não medições de
latência ou garantias de agendamento em hardware.

O firmware usa backoff de 1–60 s com jitter após falhas; a progressão não reinicia
após uma sessão. No simulador, rejeição de certificado ou integridade interrompe
as tentativas; erro de transporte aplica backoff. Uma nova conexão sempre negocia
novo `sid`; não retoma comandos ou estado criptográfico da anterior.

# Relatório técnico de auditoria e correções

Base: `59ca97f7209bab3c7197dd069edd541725b3e83b`. Data: 2026-11-22.
O [diagnóstico inicial](AUDIT_INITIAL.md) foi registrado em commit próprio antes de
modificar a implementação. O objetivo foi corrigir comportamento demonstrável e
construir evidências reproduzíveis, preservando servidor Python, agente C com dois
núcleos, fila limitada e TinyUSB.

## Resultado por achado

| ID | Severidade inicial | Correção / evidência | Limitação residual |
|---|---|---|---|
| A01 | Alta | Codec C v2 escapa/desfaz escapes; HMAC sobre bytes corretos; vetores Python→C e C→Python e TLS mbedTLS→Python passam | Protocolo v1 incompatível, atualizar todos os componentes |
| A02 | Alta | Objeto plano, tipos/duplicatas/tamanhos validados; erros terminais em vez de exceções inesperadas | Não constitui prova formal de ausência de bugs |
| A03 | Alta | Handshake em worker limitado, prazo de frame, autenticação, fechamento em finally, admissão global | DoS ainda possível dentro dos limites |
| A04 | Alta | HMAC obrigatório, dois nonces, sid, direção, sequência exata; testes de replay/reflexão/reordenação | Segredo comprometido permite agir como peer autorizado |
| A05 | Alta | SDK/placa antes do init; lwIP/TinyUSB configurados; BIO raw sem POSIX; PSA, PEM, RSA-PSS; builds separados ELF/UF2 | TLS host não valida Wi-Fi nem execução física |
| A06 | Alta | Prazo total por comando; fila cancelada em falha; consumo sem sleep bloqueante; ACK aguarda fila/press-release/delay | Efeito já emitido não pode ser revertido; agendamento físico não medido |
| A07 | Média | Seção crítica com propriedade clara, testes FIFO concorrentes; GET_REPORT retorna zero | Corrupção/race física original não foi demonstrada; stress usa pthreads |
| A08 | Média | Subtração unsigned de tempo decorrido; rate limit testado em boot/limite/wrap; agendamento HID usa timer 64 bits | Operação prolongada no dispositivo pendente |
| A09 | Média | Lock por transação, registry protegido, parser rejeita script inteiro antes de envio, stop na primeira rejeição | Sem identificação persistente por agente/mTLS |
| A10 | Média | Parser plano limitado, rejeição de assinatura ausente/tamanho errado, corpo e comando estritos | ASCII/US-QWERTY; sem Unicode e sem múltiplas teclas normais no combo |
| A11 | Alta | Runner substituído por unittest com saída não zero, sem aprovação manual fictícia; C real e TLS real incluídos | Critérios de host não substituem critérios de hardware |
| A12 | Média | Simulador só registra eventos em deque limitada; removida dependência pyautogui e logs de payload | Simulação não modela temporização de USB |
| A13 | Média | Config local ignorada; CA nova sem sobrescrita, umask 077; removida instrução de expor diretório de chaves por HTTP | Credenciais continuam recuperáveis do dispositivo/imagem |
| A14 | Média | README sem afirmações físicas/benchmarks fictícios; documentação vinculada a logs e matriz | Projeto ainda não é qualificado para produção |
| A15 | Média | Reconexão Wi-Fi com prazos; backoff limitado; EOF aplica espera no simulador; rate persiste entre sessões | Backoff não reinicia após sessão; reiniciar o processo zera rate |
| A16 | Nova / dependência | Revisão dos avisos de novembro de 2026 motivou mbedTLS externo 3.6.8 e repetição de builds/TLS | Revisão não equivale a varredura completa de toda a cadeia embarcada |

## Mudanças de contrato justificadas

1. Protocolo v2 substitui o envelope quebrado e sem replay protection. Não há fallback
   silencioso para HMAC opcional ou protocolo antigo.
2. Simulador deixou de injetar teclas no desktop: esse comportamento violava o
   isolamento necessário para testes automatizados. A capacidade HID do firmware
   permanece; nenhum novo mecanismo ofensivo foi introduzido.
3. Transporte usa endereço IPv4 separado da identidade de certificado; não resolve
   DNS no dispositivo. A restrição está explícita na configuração.
4. A fila continua SPSC limitada, mas a sincronização é uma seção crítica, sem
   afirmação de lock-free. Isso permite cancelamento seguro pelo produtor e evita
   escrita concorrente não coordenada no índice do consumidor.
5. Sucesso no firmware espera o estado ocioso da fila e endpoint; não significa
   que o aplicativo no host processou o input. Simulador confirma só eventos gravados.

## Falhas encontradas durante a validação

As primeiras tentativas não foram marcadas como aprovadas: colisão do nome do header
mbedTLS com o default upstream, ausência do hook de tempo em milissegundos, ausência
de RSA-PSS/X.509 e stack maior que a scratch Y impediram build/handshake. Os fixes
foram validados por novas compilações e teste TLS com a configuração real. A descoberta
dos avisos recentes exigiu ainda trocar mbedTLS 3.6.6 por 3.6.8 e repetir as evidências.

O LeakSanitizer não funcionou no sandbox local sob ptrace. ASan/UBSan executaram com
LSan desligado; a matriz distingue esse resultado. O workflow tenta LSan normalmente.
Não foi executado payload de teclado, shell remoto ou teste fora do loopback.

## O que pode ser defendido tecnicamente

- O protocolo implementado tem especificação e limites coerentes entre Python e C.
- Há reprodução de falhas iniciais e regressões com critérios observáveis.
- Há compilação por placa com fonte e toolchain fixadas; isso não é teste físico.
- Há teste de TLS 1.3/certificados com a configuração mbedTLS real em host.
- Há tratamento explícito de falha parcial, cancelamento, limites e propriedade de recursos.

## O que ainda impede declarar qualificação física/produção

Hora civil confiável, medições de heap/stack em falha, operação USB/Wi-Fi simultânea,
layout/estado do host, reset/suspend/unplug, entropia física, provisionamento individual
e proteção de flash. A lista completa e os pressupostos estão em
[SECURITY.md](SECURITY.md); os resultados objetivos estão em [VALIDATION.md](VALIDATION.md).

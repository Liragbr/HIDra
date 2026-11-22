# Isolamento do laboratório

A suíte atual não precisa de VirtualBox, Windows Sandbox nem pyautogui. Execute
`python3 test/run_tests.py` na raiz: ela cria endpoints TLS em loopback e verifica
eventos em memória. O simulador não digita na janela em foco.

Se optar por VMs, execute servidor e simulador dentro de ambientes próprios, em
rede interna/host-only. Exponha a porta apenas à VM autorizada. Use certificados com
SAN correspondente e transfira somente `ca.pem`, nunca as chaves privadas.

O host Windows e suas janelas não são alvos automáticos do teste. Redirecionamento
USB, enumeração de um Pico e entrada de teclado no guest precisam de ensaios próprios;
não há resultado físico ou compatibilidade Windows/VirtualBox comprovados aqui.

Procedimentos atualizados: [laboratório](../docs/LAB.md),
[modelo de ameaças](../docs/SECURITY.md), [matriz de validação](../docs/VALIDATION.md).

#!/bin/sh
# rollback-demo.sh — Restaurar estado del firewall post-demo
# VM101 OPNsense — Ejecutar como root
#
# Uso:
#   sh rollback-demo.sh
#
# Vacía la tabla PF de bloqueo de Wazuh Active Response
# y elimina los alias IP de la VM100 Kali si persisten

echo "[rollback] Vaciando tabla __wazuh_agent_drop..."
pfctl -t __wazuh_agent_drop -T flush
echo "[rollback] IPs bloqueadas eliminadas:"
pfctl -t __wazuh_agent_drop -T show 2>/dev/null || echo "  (tabla vacía)"

echo "[rollback] Verificando reglas activas..."
pfctl -s rules | grep wazuh || echo "  (ninguna regla wazuh activa)"

echo "[rollback] DONE — Laboratorio listo para nueva ejecución."

# CLAUDE.md — SOC Zero Trust Lab

Contexto para Claude Code al trabajar en este repositorio.

## Proyecto

Implementación de un SOC Zero Trust con herramientas open source sobre 11 VMs en Proxmox VE.
TFG ASIR — IES Valle Inclán 2025-2026.

## Estructura clave

```
src/ztt_framework.py      # Tool ZTT v1.1 — script de ataque/validación (866 líneas)
src/preparar.sh           # Limpieza pre-demo (alias IP)
config/wazuh/             # Reglas y decoders de Wazuh
config/nginx/             # Config Nginx VM103
config/fail2ban/          # Jails y acciones Fail2Ban
config/opnsense/          # Script rollback PF
web/el-heraldo-pyongyang/ # Web señuelo (5 MB — imágenes en base64)
docs/                     # Guías de instalación y fases ZTT
```

## Reglas importantes

- El script `src/ztt_framework.py` se llama **"Tool ZTT v1.1"** — nunca "framework"
- Las reglas Wazuh `100005`, `100010`, `100011`, `100014`, `100020`, `100040` son sagradas — no modificar IDs
- La web señuelo se llama "El Heraldo de Pyongyang" — config nginx: `supreme-hair-trends`
- Active Response: Cowrie → Agente 010 → Wazuh Manager → AR → Agente 009 → pfctl

## Ejecutar la demo

```bash
# En VM100 Kali (172.17.0.167) como root:
sudo python3 src/ztt_framework.py --status      # verificar 3/3 ONLINE
sudo python3 src/ztt_framework.py --tribunal    # demo con pausas
sudo python3 src/ztt_framework.py --espectaculo # demo continua
sudo python3 src/ztt_framework.py --fase 8      # fase concreta
```

## Seguridad

No hay credenciales en este repositorio. El CI (`.github/workflows/security-scan.yml`)
bloquea cualquier push que contenga contraseñas, claves privadas o combinaciones IP+credencial.

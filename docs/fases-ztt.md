# Fases de la Tool ZTT v1.1

Descripción técnica detallada de las 9 fases de ataque que ejecuta la Tool ZTT sobre el laboratorio.

---

## Requisitos previos

```bash
# VM100 Kali — verificar estado de los 3 objetivos
sudo python3 src/ztt_framework.py --status
# Salida esperada: 3/3 ONLINE (VM103 · VM106 · VM101)
```

---

## Fase 0 — Check de estado

**Vector:** Verificación de conectividad  
**Herramienta:** ping / socket  
**Targets:** VM106 (T-Pot), VM103 (Nginx), VM101 (OPNsense WAN)

Comprueba que los tres objetivos responden antes de iniciar la secuencia. Si alguno no responde, la tool aborta.

```
[0/3] 172.17.0.16   T-Pot    ONLINE
[1/3] 172.17.0.13   Nginx    ONLINE
[2/3] 203.0.113.10  OPNsense ONLINE
```

---

## Fase 1 — Reconocimiento de puertos

**Vector:** Port scanning  
**Herramienta:** RustScan 2.3.0  
**Target:** 172.17.0.16 (T-Pot / VM106)  
**Alerta Wazuh:** —

RustScan descubre los puertos abiertos en T-Pot. El honeypot expone deliberadamente SSH (22/tcp emulado por Cowrie), SMB (445/tcp) y MSSQL (1433/tcp) entre otros.

```bash
rustscan -a 172.17.0.16 --ulimit 5000 -t 2000
```

---

## Fase 2 — Enumeración web

**Vector:** Directory fuzzing  
**Herramienta:** ffuf v2.1.0-dev  
**Target:** 172.17.0.13 (Nginx VM103)  
**Alerta Wazuh:** `100014` (lvl 10) — ffuf detectado en logs Nginx  
**Nota:** Regla `100005` (frecuencia) no disparó por rate-limiting 503 de Nginx

```bash
ffuf -u http://172.17.0.13/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -mc 200,301,302,403 -t 50
```

Nginx aplica rate-limiting (`req_limit_per_ip` 10r/s burst=20) y responde 503 a las peticiones que superan el umbral. La regla `100014` detecta el patrón de User-Agent de ffuf en los logs.

---

## Fase 3 — Honeypot SSH éxito (Cowrie)

**Vector:** Brute force SSH + sesión interactiva  
**Herramienta:** Hydra v9.6 + ssh  
**Target:** 172.17.0.16:22 (Cowrie en T-Pot / VM106)  
**Alerta Wazuh:** `100011` (lvl 14) — SSH exitoso en honeypot  
**Respuesta:** Active Response → PF block (latencia < 5 s)

Hydra realiza fuerza bruta con wordlist personalizada. Cowrie acepta la conexión con `root:12345` (posición 8 de la lista). El Agente 010 reporta el éxito al Manager, que dispara el AR hacia el Agente 009 (OPNsense), bloqueando la IP atacante en la tabla `__wazuh_agent_drop` de PF.

```bash
hydra -l root -P /home/kali/demo/wordlist_demo.txt ssh://172.17.0.16 -t 4
```

---

## Fase 4 — Honeypot SSH fallo (IP alias)

**Vector:** SSH fallo desde IP alias  
**Herramienta:** ssh con `-b` (bind source IP)  
**Target:** 172.17.0.16:22 (Cowrie)  
**IP origen:** 172.17.0.200 (alias creado en eth0 de VM100)  
**Alerta Wazuh:** `100010` → acumulación → `100040` (lvl 15) CRITICAL  
**Respuesta:** AR → PF block sobre 172.17.0.200

```bash
sudo ip addr add 172.17.0.200/24 dev eth0
ssh -b 172.17.0.200 root@172.17.0.16  # intento × 3 → fail
```

---

## Fase 5 — Rollback PF

**Vector:** —  
**Herramienta:** `rollback-demo.sh` en VM101  
**Acción:** Vacía la tabla `__wazuh_agent_drop` de PF

Restaura el estado del firewall para poder repetir el ciclo de demostración.

---

## Fase 6 — Fail2Ban doble capa

**Vector:** SSH fallo desde IP alias (misma .200)  
**Herramienta:** ssh con `-b`  
**Target:** 172.17.0.13:22 (VM103 — Fail2Ban activo)  
**Alerta Wazuh:** `100040` (lvl 15)  
**Respuesta:** Fail2Ban → iptables local + Wazuh AR → PF perimetral

Doble bloqueo: Fail2Ban actúa primero localmente (iptables en VM103), y simultáneamente su acción custom `wazuh-syslog` genera un log que Wazuh procesa para disparar el AR perimetral en OPNsense.

---

## Fase 7 — Rollback Fail2Ban

**Vector:** —  
**Herramienta:** `fail2ban-client unban`  
**Acción:** Desbanea la IP alias del jail activo

```bash
sudo fail2ban-client set sshd unbanip 172.17.0.200
```

---

## Fase 8 — Dionaea SMB + MSSQL

**Vector:** Exploit SMB + conexión MSSQL a honeypot  
**Herramienta:** impacket-scripts  
**Target:** 172.17.0.16:445, 172.17.0.16:1433 (Dionaea en T-Pot / VM106)  
**Alerta Wazuh:** `100020` × 2 — conexión exploit detectada

```bash
# SMB (puerto 445)
impacket-smbclient //172.17.0.16/share -U guest

# MSSQL (puerto 1433)
impacket-mssqlclient 172.17.0.16 -port 1433
```

Dionaea captura las conexiones, registra los payloads en su base de datos interna y emite logs que el Agente 010 reenvía a Wazuh. La regla `100020` se dispara dos veces (una por protocolo).

---

## Resultados de validación completa

| Fase | Detección | Respuesta | TP/FP/FN |
|------|-----------|-----------|----------|
| 0 | — | — | — |
| 1 | — | — | — |
| 2 | 100014 ×19 | — | 19 TP |
| 3 | 100011 lvl14 | AR PF ✅ < 5s | 1 TP |
| 4 | 100040 lvl15 | AR PF ✅ < 5s | 1 TP |
| 5 | — | — | — |
| 6 | 100040 lvl15 | iptables + PF ✅ | 1 TP |
| 7 | — | — | — |
| 8 | 100020 ×2 | — | 2 TP |
| **Total** | | | **~29 TP · 0 FP · 1 FN** |

*FN: regla 100005 (ffuf frecuencia) — Nginx respondió 503 por rate-limit antes de acumular el umbral requerido.*

# El Heraldo de Pyongyang — Web Cliente Simulado

Sitio web de un **cliente simulado** que ha contratado los servicios del SOC Zero Trust implementado en este proyecto. Representa una organización ficticia cuya infraestructura web está protegida y monitorizada por el sistema de detección y respuesta activa.

## Rol en el laboratorio

| Componente | Detalle |
|---|---|
| **Servidor** | VM103 — Nginx 1.18.0 · Ubuntu 20.04 · `172.17.0.13` |
| **Protección** | Fail2Ban 0.11.1 + reglas personalizadas Wazuh (agente 008) |
| **Monitorización** | Tráfico HTTP auditado por Wazuh → alertas 100001-100009 |
| **Cobertura IDS** | Suricata 8.0.4 en OPNsense inspecciona el tráfico hacia este host |

## Estructura del sitio

```
el-heraldo-pyongyang/
├── index.html          ← Portada principal (imágenes embebidas en base64)
├── capilar/            ← Sección Capilar
├── cultura/            ← Sección Cultura
├── cosechas/           ← Sección Cosechas
├── opinion/            ← Sección Opinión
└── politica/           ← Sección Política
```

## Flujo de detección sobre esta web

La Tool ZTT v1.1 ejecuta en la **Fase 2** un escaneo de directorios con `ffuf` contra este servidor, lo que dispara la regla Wazuh `100014` (ffuf detectado) y la `100005` (enumeración web). Fail2Ban detecta el exceso de peticiones y bloquea la IP atacante a nivel de `iptables`, mientras Wazuh consolida la alerta.

> El sitio web es ficticio. Cualquier similitud con publicaciones reales es coincidencia.

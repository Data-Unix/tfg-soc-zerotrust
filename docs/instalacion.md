# Guía de Instalación del Laboratorio

> ⚠️ **Entorno académico.** Diseñado para Proxmox VE sobre hardware dedicado.
> No desplegar en producción sin revisión de seguridad completa.

---

## Hardware recomendado

| Componente | Mínimo | Utilizado en TFG |
|-----------|--------|-----------------|
| CPU | 6 cores / 12 threads | Intel/AMD 6+ cores |
| RAM | 32 GB | 32 GB DDR4 |
| Almacenamiento | SSD 256 GB + HDD 1 TB | SSD sistema + HDD datos |
| Red | 1 Gbps | Gigabit Ethernet |

---

## Requisitos de software

- **Proxmox VE** instalado con 4 bridges de red configurados:
  - `vmbr0` → WAN (203.0.113.0/24)
  - `vmbr1` → LAN_DMZ (172.17.0.0/24)
  - `vmbr2` → LAN_INTERNA (172.18.0.0/24)
  - `vmbr3` → LAN_MNG (172.16.0.0/24)
- Acceso a Internet para descarga de ISOs y paquetes

---

## Orden de despliegue

### 1. Infraestructura base

```bash
# VM101 — OPNsense (Firewall perimetral)
# Descargar OPNsense .iso → crear VM (2 vCPU, 4 GB RAM, 20 GB)
# Interfaces: vtnet0=vmbr0(WAN), vtnet1=vmbr1(DMZ), vtnet2=vmbr2(INT), vtnet3=vmbr3(MNG)
# Instalar Suricata 8.0.4 desde System → Firmware → Plugins
# Activar IDS en interfaz WAN
```

```bash
# VM102 — Wazuh Manager 4.14.1
# Ubuntu 22.04 LTS → instalar via curl installer
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
bash wazuh-install.sh -a
# Copiar local_rules.xml y tpot_decoders.xml a /var/ossec/etc/
```

```bash
# VM103 — Nginx + Fail2Ban
# Ubuntu 20.04 LTS
sudo apt install nginx fail2ban
# Copiar configs de config/nginx/ y config/fail2ban/
# Desplegar web señuelo en /var/www/html/
```

### 2. Honeypots

```bash
# VM106 — T-Pot v24.04.1
# Debian 11 → instalar T-Pot STANDARD edition
git clone https://github.com/telekom-security/tpotce
cd tpotce && sudo ./install.sh --type=STANDARD
# Registrar agente Wazuh 010 apuntando a VM102
```

### 3. Identidad y acceso

```bash
# VM105 — Active Directory DC01
# Windows Server 2022 CORE
# Install-WindowsFeature AD-Domain-Services
# Install-ADDSForest -DomainName "lab.tfg.local"

# VM107 — Authentik 2026.2.2
# Ubuntu 22.04 + Docker
# Configurar LDAP Outpost apuntando a AD DC01

# VM108 — Nginx Proxy Manager 2.14.0
# Docker Compose con 8 proxy hosts → todos con SSL wildcard *.lab.tfg.local
```

### 4. Endpoints y servicios

```bash
# VM104 — Windows 10 LTSC 21H2
# Unir a dominio lab.tfg.local
# Instalar agente Wazuh 011

# VM109 — Mail Server
# Ubuntu 24.04 + docker-mailserver v15.1.0 + Roundcube
# FQDN: mail.lab.tfg.local → NPM

# VM110 — Apache Guacamole 1.6.0
# Ubuntu 24.04 + Docker
# RDP hacia VM104/VM105, SSH hacia el resto
# FQDN: guacamole.lab.tfg.local → NPM
```

### 5. Atacante simulado

```bash
# VM100 — Kali Linux 2025.4
# Instalar dependencias de la Tool ZTT:
sudo apt install -y hydra ffuf rustscan sshpass impacket-scripts
pip install rich

# Descomprimir wordlist
gunzip /usr/share/wordlists/rockyou.txt.gz

# Copiar Tool ZTT al directorio de trabajo
mkdir -p /home/kali/demo/
cp src/ztt_framework.py /home/kali/demo/
cp src/preparar.sh /home/kali/demo/
chmod +x /home/kali/demo/preparar.sh
```

### 6. Active Response — configuración final

En VM102 (Wazuh Manager), configurar el bloque AR en `ossec.conf`:

```xml
<active-response>
  <command>opnsense-fw</command>
  <location>defined-agent</location>
  <agent_id>009</agent_id>
  <rules_id>100011,100040</rules_id>
  <timeout>no</timeout>
</active-response>
```

En VM101 (OPNsense / Agente 009), el script AR ejecuta:

```bash
pfctl -t __wazuh_agent_drop -T add <IP_ATACANTE>
```

---

## Validación del despliegue

```bash
# Verificar conectividad y estado de los 3 targets
sudo python3 /home/kali/demo/ztt_framework.py --status
# Esperado: 3/3 ONLINE

# Demo completa para tribunal (con pausas explicativas)
sudo python3 /home/kali/demo/ztt_framework.py --tribunal

# Demo sin pausas (grabación)
sudo python3 /home/kali/demo/ztt_framework.py --espectaculo

# Fase concreta
sudo python3 /home/kali/demo/ztt_framework.py --fase 8
```

---

## Troubleshooting

| Síntoma | Causa probable | Solución |
|---------|---------------|----------|
| Active Response no bloquea | Agente 009 desconectado | `systemctl restart wazuh-agent` en VM101 |
| Cowrie no responde al SSH | T-Pot reiniciando | Esperar 2-3 min tras arranque de VM106 |
| ffuf devuelve 503 | Rate-limit Nginx activo | Esperado — ver Fase 2 y regla 100005 |
| `--status` devuelve 2/3 ONLINE | VM106 o VM103 apagadas | Arrancar VMs en Proxmox |

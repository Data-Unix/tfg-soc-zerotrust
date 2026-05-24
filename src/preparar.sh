#!/bin/bash
echo "[*] Limpiando alias IP..."
sudo ip addr flush dev eth0 label "eth0:*" 2>/dev/null || true
for i in $(seq 0 9); do sudo ip addr del 172.17.0.20${i}/24 dev eth0 2>/dev/null; done
echo "[+] Kali listo"

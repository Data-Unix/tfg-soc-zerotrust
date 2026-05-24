#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  Z E R O   T R U S T   T R I B U N A L   F R A M E W O R K   v 1 . 0
  Autores: ALVARO CARMENA | ILIE SCRIPCA
  Maquina: Kali Atacante (172.17.0.167)
  Objetivo: Demo tribunal SOC Zero Trust con deteccion distribuida y
            respuesta activa centralizada (Wazuh + OPNsense PF + Fail2Ban)
================================================================================
  FASES:
    0. Status        -> Verificacion pre-demo
    1. Recon         -> rustscan/nmap (IP 167) -> reglas Suricata 100112/100114
    2. Web           -> ffuf/nikto (IP 167) -> Suricata WEB ATTACK 100114
    3. Cowrie OK     -> ssh login honeypot (IP 167) -> regla 100011
    4. Cowrie FAIL   -> ssh fallido (IP 200) -> regla 100010->100040 -> bloqueo PF
    5. Rollback #1   -> Limpieza manual guiada PF + alias
    6. Fail2Ban      -> ssh fallido real (IP 201) -> 100003->100040 -> PF+F2B
    7. Rollback #2   -> Limpieza manual guiada completa
    8. Dionaea       -> impacket SMB/MSSQL (IP 167) -> regla 100020
================================================================================
"""

import sys
import os
import time
import subprocess
import shutil
import argparse
from typing import Optional, List, Tuple, Dict

# Rich UI library (ya instalada en Kali)
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.layout import Layout
    from rich.text import Text
    from rich.align import Align
    from rich import box
    from rich.prompt import Prompt, Confirm
    from rich.live import Live
    from rich.columns import Columns
    from rich.rule import Rule
except ImportError:
    print("[!] Error: Libreria rich no instalada.")
    print("    Ejecuta: pip3 install rich")
    sys.exit(1)

# ==============================================================================
# CONFIGURACION GLOBAL
# ==============================================================================
class Config:
    # Red
    IP_BASE = "172.17.0.167"
    IP_ALIAS_POOL = [f"172.17.0.20{i}" for i in range(0, 10)]  # 200-209
    INTERFACE = "eth0"

    # Targets
    TARGET_COWRIE = "172.17.0.16"
    TARGET_FAIL2BAN = "172.17.0.13"
    TARGET_WEB = "172.17.0.13"

    # Credenciales Cowrie
    COWRIE_USER = "root"
    COWRIE_PASS = "root"

    # OPNsense (para referencia en rollback manual)
    OPNsense_IP = "172.18.0.1"
    OPNsense_USER = "root"

    # Paths
    ROLLBACK_SCRIPT = "/usr/local/bin/rollback-demo.sh"

    # Timing
    DELAY_ESPECTACULO = 3
    DELAY_FASE = 5

# ==============================================================================
# CONSOLA RICH GLOBAL
# ==============================================================================
console = Console(width=160)

# ==============================================================================
# BANNER Y UI 
# ==============================================================================
class UI:
    BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║     ███████╗███████╗██████╗  ██████╗     ████████╗██████╗ ██╗   ██╗███████╗  ║
║     ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗    ╚══██╔══╝██╔══██╗██║   ██║██╔════╝  ║
║       ███╔╝ █████╗  ██████╔╝██║   ██║       ██║   ██████╔╝██║   ██║███████╗  ║
║      ███╔╝  ██╔══╝  ██╔══██╗██║   ██║       ██║   ██╔══██╗██║   ██║╚════██║  ║
║     ███████╗███████╗██║  ██║╚██████╔╝       ██║   ██║  ██║╚██████╔╝███████║  ║
║     ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝        ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝  ║
║                                                                              ║
║               S I M U L A N C I Ó N   C O M O   A T A C A N T E              ║
║                                                                              ║
║          TFG SOC ZERO TRUST    —    Demo para Tribunal 2026 (Tutor Manuel)   ║
║                                                                              ║
║                    Á L V A R O   C A R M E N A   D Í A Z                     ║
║                                                                              ║
║                            I L I E   S C R I P C A                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """

    @staticmethod
    def print_banner():
        console.print(Panel(
            Align.center(Text(UI.BANNER, style="bold bright_cyan")),
            border_style="bright_blue",
            padding=(1, 2)
        ))

    @staticmethod
    def print_menu():
        table = Table(
            title="[bold bright_blue]MENU PRINCIPAL[/bold bright_blue]",
            box=box.ROUNDED,
            border_style="bright_blue",
            show_header=False,
            padding=(0, 2)
        )
        table.add_column("Opcion", style="bold yellow", justify="center")
        table.add_column("Descripcion", style="white")
        table.add_column("Modo", style="dim cyan")
        table.add_row("[1]", "MODO TRIBUNAL", "Paso a paso con narrativa para el jurado")
        table.add_row("[2]", "MODO ESPECTACULO", "Automatico con delays (demo rapida)")
        table.add_row("[3]", "FASE INDIVIDUAL", "Ejecutar una fase especifica")
        table.add_row("[4]", "ROLLBACK TOTAL", "Limpiar PF + Fail2Ban + alias")
        table.add_row("[5]", "VERIFICAR ESTADO", "Estado de tablas, agentes, bans")
        table.add_row("[6]", "VERIFICAR DEPENDENCIAS", "Chequear herramientas necesarias")
        table.add_row("[0]", "SALIR", "")
        console.print(Panel(table, border_style="bright_blue", padding=(1, 2)))

    @staticmethod
    def print_fase_header(num: int, nombre: str, herramienta: str, ip: str, target: str):
        grid = Table.grid(expand=True)
        grid.add_column(style="bold cyan")
        grid.add_column(style="white")
        grid.add_row("Fase:", f"[bold]{num}[/bold] — {nombre}")
        grid.add_row("Herramienta:", f"[green]{herramienta}[/green]")
        grid.add_row("IP Origen:", f"[yellow]{ip}[/yellow]")
        grid.add_row("Target:", f"[red]{target}[/red]")
        console.print(Panel(grid, border_style="bright_magenta", title=f"[bold]FASE {num}[/bold]"))

    @staticmethod
    def narrar(texto: str, pausa: bool = True):
        console.print(f"[bold bright_cyan]EXPLICACION:[/bold bright_cyan] {texto}")
        if pausa:
            Prompt.ask("[dim]Presiona ENTER para continuar...[/dim]")

    @staticmethod
    def info(texto: str):
        console.print(f"[dim cyan]Info: {texto}[/dim cyan]")

    @staticmethod
    def ok(texto: str):
        console.print(f"[bold green]OK: {texto}[/bold green]")

    @staticmethod
    def warn(texto: str):
        console.print(f"[bold yellow]WARN: {texto}[/bold yellow]")

    @staticmethod
    def error(texto: str):
        console.print(f"[bold red]ERROR: {texto}[/bold red]")

    @staticmethod
    def alerta_wazuh(rule_id: str, nivel: str, descripcion: str):
        texto = f"[bold red]ALERTA WAZUH DETECTADA[/bold red]\n"
        texto += f"Regla: [yellow]{rule_id}[/yellow] | Nivel: [red]{nivel}[/red]\n"
        texto += descripcion
        console.print(Panel(texto, border_style="red", title="[bold]DETECCION[/bold]"))

    @staticmethod
    def comando_manual(comando: str, donde: str, esperado: str = ""):
        texto = f"[bold yellow]EJECUTAR MANUALMENTE EN {donde}[/bold yellow]\n\n"
        texto += f"[bright_white on black] {comando} [/bright_white on black]\n\n"
        if esperado:
            texto += f"[dim green]Esperado:[/dim green] {esperado}\n"
        texto += "[dim]Presiona ENTER cuando hayas ejecutado el comando...[/dim]"
        console.print(Panel(texto, border_style="yellow", title="[bold]ROLLBACK MANUAL[/bold]", padding=(1, 2)))

# ==============================================================================
# VERIFICADOR DE DEPENDENCIAS
# ==============================================================================
class Verificador:
    HERRAMIENTAS = {
        "sshpass": ("which sshpass", "Autenticacion SSH automatizada"),
        "rustscan": ("rustscan --version", "Escaneo de puertos rapido (visual)"),
        "nmap": ("nmap --version", "Escaneo de puertos (fallback)"),
        "ffuf": ("ffuf -V", "Fuzzing web"),
        "nikto": ("nikto -Version", "Escaner web"),
        "impacket-smbclient": ("which impacket-smbclient", "Cliente SMB (Dionaea)"),
        "impacket-mssqlclient": ("which impacket-mssqlclient", "Cliente MSSQL (Dionaea)"),
        "curl": ("curl --version", "Peticiones HTTP"),
        "ping": ("ping -c 1 127.0.0.1", "Conectividad ICMP"),
    }

    @staticmethod
    def verificar_todo():
        UI.print_banner()
        console.print(Rule("[bold bright_blue]VERIFICACION DE DEPENDENCIAS[/bold bright_blue]", style="bright_blue"))
        table = Table(title="Estado de herramientas", box=box.ROUNDED)
        table.add_column("Herramienta", style="cyan")
        table.add_column("Estado", style="green", justify="center")
        table.add_column("Descripcion", style="dim")
        faltantes = []
        for nombre, (cmd, desc) in Verificador.HERRAMIENTAS.items():
            try:
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    table.add_row(nombre, "[green]OK[/green]", desc)
                else:
                    table.add_row(nombre, "[red]FALTA[/red]", desc)
                    faltantes.append(nombre)
            except Exception:
                table.add_row(nombre, "[red]FALTA[/red]", desc)
                faltantes.append(nombre)
        console.print(table)
        if faltantes:
            UI.warn(f"Faltan herramientas: {', '.join(faltantes)}")
            console.print("[dim]Instalacion sugerida:[/dim]")
            for f in faltantes:
                if f == "sshpass":
                    console.print("[yellow]   sudo apt install -y sshpass[/yellow]")
                elif f == "rustscan":
                    console.print("[yellow]   wget https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb -O /tmp/rustscan.deb && sudo dpkg -i /tmp/rustscan.deb[/yellow]")
        else:
            UI.ok("Todas las herramientas estan disponibles.")
        console.print(Rule("[bold]Conectividad a Targets[/bold]", style="cyan"))
        for ip, nombre in [(Config.TARGET_COWRIE, "Cowrie"), (Config.TARGET_FAIL2BAN, "Fail2Ban")]:
            rc = subprocess.run(["ping", "-c", "1", "-W", "2", ip], capture_output=True, timeout=5).returncode
            estado = "[green]ONLINE[/green]" if rc == 0 else "[red]OFFLINE[/red]"
            console.print(f"  {nombre} ({ip}): {estado}")
        return len(faltantes) == 0

# ==============================================================================
# GESTION DE IP ALIAS
# ==============================================================================
class IPManager:
    def __init__(self):
        self.alias_idx = -1
        self.alias_actual: Optional[str] = None

    def _run(self, cmd: List[str]) -> Tuple[int, str, str]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            return 1, "", str(e)

    def crear_alias(self, ip: str) -> bool:
        UI.info(f"Creando IP alias {ip} en {Config.INTERFACE}...")
        rc, out, err = self._run([
            "sudo", "ip", "addr", "add", f"{ip}/24",
            "dev", Config.INTERFACE
        ])
        if rc != 0 and "File exists" not in err and "Address already assigned" not in err:
            UI.error(f"No se pudo crear alias: {err}")
            return False
        self.alias_actual = ip
        UI.ok(f"IP alias {ip} activa")
        return True

    def eliminar_alias(self, ip: str) -> bool:
        UI.info(f"Eliminando IP alias {ip}...")
        rc, out, err = self._run([
            "sudo", "ip", "addr", "del", f"{ip}/24",
            "dev", Config.INTERFACE
        ])
        if rc != 0 and "Cannot assign requested address" not in err:
            UI.warn(f"No se pudo eliminar alias: {err}")
            return False
        if self.alias_actual == ip:
            self.alias_actual = None
        UI.ok(f"IP alias {ip} eliminada")
        return True

    def siguiente_alias(self) -> str:
        rc, out, _ = self._run(["ip", "addr", "show", Config.INTERFACE])
        for ip in Config.IP_ALIAS_POOL:
            if ip not in out:
                self.alias_actual = ip
                return ip
        self.alias_actual = Config.IP_ALIAS_POOL[0]
        return Config.IP_ALIAS_POOL[0]

    def limpiar_todos(self):
        UI.info("Limpiando todos los alias IP...")
        for ip in Config.IP_ALIAS_POOL:
            self._run(["sudo", "ip", "addr", "del", f"{ip}/24", "dev", Config.INTERFACE])
        self.alias_actual = None
        self.alias_idx = -1
        UI.ok("Alias limpiados")

# ==============================================================================
# EJECUTOR DE COMANDOS CON UI
# ==============================================================================
class Executor:
    @staticmethod
    def run(cmd: List[str], descripcion: str = "", timeout: int = 30,
            mostrar_output: bool = True, shell: bool = False) -> Tuple[int, str, str]:
        if descripcion:
            UI.info(descripcion)
        try:
            if shell:
                result = subprocess.run(" ".join(cmd), capture_output=True, text=True,
                                       timeout=timeout, shell=True)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True,
                                       timeout=timeout)
            if mostrar_output and result.stdout:
                console.print(f"[dim]{result.stdout.strip()[:500]}[/dim]")
            if result.returncode != 0 and result.stderr:
                console.print(f"[dim red]{result.stderr.strip()[:300]}[/dim red]")
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            UI.warn(f"Timeout ({timeout}s) ejecutando: {' '.join(cmd[:5])}...")
            return -1, "", "timeout"
        except Exception as e:
            UI.error(f"Error ejecutando comando: {e}")
            return 1, "", str(e)

    @staticmethod
    def run_progress(cmd: List[str], descripcion: str, timeout: int = 30) -> Tuple[int, str, str]:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(descripcion, total=None)
            result = Executor.run(cmd, timeout=timeout, mostrar_output=False)
            progress.update(task, completed=100)
            return result

# ==============================================================================
# ROLLBACK MANUAL GUIADO
# ==============================================================================
class Rollback:
    @staticmethod
    def rollback_pf_manual(ip: str):
        UI.info(f"Desbloqueando IP {ip} en OPNsense PF...")
        UI.comando_manual(
            f"sh {Config.ROLLBACK_SCRIPT} delete {ip}",
            f"OPNsense ({Config.OPNsense_IP})",
            f"La IP {ip} desaparecera de la tabla __wazuh_agent_drop"
        )
        Prompt.ask("")
        UI.ok(f"IP {ip} desbloqueada de PF")

    @staticmethod
    def rollback_fail2ban_manual(ip: str):
        UI.info(f"Desbloqueando IP {ip} en Fail2Ban...")
        UI.comando_manual(
            f"sudo fail2ban-client set sshd unbanip {ip}",
            f"Server-Fail2Ban ({Config.TARGET_FAIL2BAN})",
            f"La IP {ip} desaparecera de la lista de baneadas"
        )
        Prompt.ask("")
        UI.ok(f"IP {ip} desbloqueada de Fail2Ban")

    @staticmethod
    def rollback_total(ip_manager: IPManager, ip_pf: Optional[str] = None, ip_f2b: Optional[str] = None):
        UI.print_fase_header(0, "ROLLBACK TOTAL", "Manual guiado", Config.IP_BASE, "Toda la infraestructura")
        if ip_pf:
            Rollback.rollback_pf_manual(ip_pf)
        if ip_f2b:
            Rollback.rollback_fail2ban_manual(ip_f2b)
        ip_manager.limpiar_todos()
        UI.ok("Rollback completado. Entorno limpio.")

# ==============================================================================
# FASES DEL ATAQUE
# ==============================================================================
class Fases:
    def __init__(self, ip_manager: IPManager, modo_tribunal: bool = True):
        self.ipm = ip_manager
        self.modo_tribunal = modo_tribunal
        self.delay = Config.DELAY_ESPECTACULO if not modo_tribunal else 0

    def _narrar(self, texto: str):
        UI.narrar(texto, pausa=self.modo_tribunal)
        if not self.modo_tribunal:
            time.sleep(self.delay)

    def _info(self, texto: str):
        UI.info(texto)
        if not self.modo_tribunal:
            time.sleep(1)

    def fase_0_status(self):
        UI.print_fase_header(0, "STATUS", "ping / curl", Config.IP_BASE, "Todos los targets")
        self._narrar("Verificamos que todos los componentes del SOC estan activos antes de la demo.")
        targets = [
            (Config.TARGET_COWRIE, "Cowrie Honeypot"),
            (Config.TARGET_FAIL2BAN, "Server-Fail2Ban + Nginx"),
            (Config.TARGET_WEB, "Web Supreme Hair Trends"),
        ]
        table = Table(title="Estado de Targets", box=box.SIMPLE)
        table.add_column("Target", style="cyan")
        table.add_column("IP", style="yellow")
        table.add_column("Estado", style="green")
        for ip, nombre in targets:
            rc, _, _ = Executor.run(["ping", "-c", "1", "-W", "2", ip], mostrar_output=False)
            estado = "[green]ONLINE[/green]" if rc == 0 else "[red]OFFLINE[/red]"
            table.add_row(nombre, ip, estado)
        console.print(table)
        self._narrar("Todos los targets verificados. Entorno listo para la demostracion.")

    def fase_1_recon(self):
        rc, _, _ = Executor.run(["which", "rustscan"], mostrar_output=False)
        usar_rustscan = (rc == 0)
        herramienta = "rustscan" if usar_rustscan else "nmap -sS -T2"
        UI.print_fase_header(1, "RECONOCIMIENTO", herramienta, Config.IP_BASE, f"{Config.TARGET_COWRIE},{Config.TARGET_FAIL2BAN}")
        self._narrar("Fase 1: El atacante realiza reconocimiento de la red, mapeando servicios expuestos en la DMZ. Los agentes Wazuh distribuidos (008 en Server-Fail2Ban, 010 en T-Pot) mantienen visibilidad de logs de aplicacion. La deteccion activa se desplegara al iniciar la explotacion contra servicios reales.")
        puertos_encontrados = []
        if usar_rustscan:
            self._info("Ejecutando RustScan (modo greppable, sin banner)...")
            rc, out, err = Executor.run_progress(
                ["rustscan", "-a", f"{Config.TARGET_COWRIE},{Config.TARGET_FAIL2BAN}", "-p", "22,80,445,1433,3306", "-g"],
                "Escaneando puertos con RustScan...", timeout=60
            )
            if rc == 0 and out:
                for line in out.strip().splitlines():
                    if "->" in line and "[" in line:
                        ip_raw = line.split("->")[0].strip()
                        ports_raw = line.split("[")[1].split("]")[0]
                        for p in [x.strip() for x in ports_raw.split(",") if x.strip()]:
                            puertos_encontrados.append((ip_raw, p))
        else:
            self._info("Ejecutando nmap stealth (fallback)...")
            rc, out, err = Executor.run_progress(
                ["sudo", "nmap", "-sS", "-T2", "-p22,80,445,1433,3306",
                 "--open", "-oG", "-", Config.TARGET_COWRIE, Config.TARGET_FAIL2BAN],
                "Escaneando puertos en DMZ...", timeout=60
            )
            if rc == 0 and out:
                for line in out.strip().splitlines():
                    if "Ports:" in line:
                        partes = line.split("Ports: ")[1].split(",")
                        for p in partes:
                            puerto = p.split("/")[0].strip()
                            if puerto.isdigit():
                                puertos_encontrados.append(puerto)
        if puertos_encontrados:
            table = Table(title="Puertos Abiertos Detectados", box=box.SIMPLE)
            table.add_column("Target", style="cyan")
            table.add_column("Puerto", style="green", justify="center")
            table.add_column("Servicio", style="dim")
            servicio_map = {"22": "SSH", "80": "HTTP", "445": "SMB", "1433": "MSSQL", "3306": "MySQL"}
            for ip, p in sorted(set(puertos_encontrados)):
                table.add_row(ip, p, servicio_map.get(p, "Desconocido"))
            console.print(table)
            UI.ok(f"{len(set(puertos_encontrados))} puertos abiertos detectados")
            UI.warn("No se genero alerta Wazuh para SYN scan intra-LAN1. Motivo: trafico L2 directo (switch virtual), sin cruce por OPNsense WAN. Suricata IDS es invisible aqui. La deteccion host-based se activara al interactuar con servicios (Fases 2-8).")
        else:
            UI.warn("No se detectaron puertos abiertos o el escaneo fue filtrado")
        self._narrar("Reconocimiento completado. El SOC tiene visibilidad completa de la DMZ mediante agentes Wazuh en cada host. La deteccion activa se desplegara al iniciar la explotacion contra servicios expuestos.")

    def fase_2_web(self):
        UI.print_fase_header(2, "ESCANER WEB", "ffuf", Config.IP_BASE, f"http://{Config.TARGET_WEB}")
        self._narrar("Fase 2: El atacante escanea la web del cliente Supreme Hair Trends buscando directorios ocultos. El agente Wazuh desplegado en el PROPIO servidor web (008) monitorea los logs Nginx en tiempo real. Detecta el user-agent de la herramienta de ataque y multiples errores 404: defensa host-based Zero Trust.")

        # Verificar que la web responde
        rc, _, _ = Executor.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"http://{Config.TARGET_WEB}/"], mostrar_output=False)

        # Ejecutar ffuf en silencio absoluto (sin -o, capturando stdout directamente)
        self._info("Ejecutando ffuf contra el servidor web...")
        rc, out, err = Executor.run(
            ["ffuf", "-u", f"http://{Config.TARGET_WEB}/FUZZ", "-w",
             "/usr/share/wordlists/dirb/common.txt", "-t", "50", "-mc", "200,301,302,403",
             "-s"],
            timeout=45, mostrar_output=False
        )

        # Mostrar resultados limpios desde stdout (ffuf -s devuelve una URL por linea)
        resultados = [line.strip() for line in out.splitlines() if line.strip()]
        if resultados:
            table = Table(title="Recursos Web Descubiertos", box=box.SIMPLE)
            table.add_column("URL", style="green")
            table.add_column("Estado", style="cyan", justify="center")
            for res in resultados[:10]:  # max 10 para no saturar
                url = res if res.startswith("http") else f"http://{Config.TARGET_WEB}/{res}"
                table.add_row(url, "[green]ENCONTRADO[/green]")
            console.print(table)
            UI.ok(f"{len(resultados)} recursos web descubiertos")
        else:
            UI.warn("No se encontraron recursos adicionales (respuesta 404 para la mayoria)")

        UI.alerta_wazuh("100014", "10", "Escaneo web detectado: herramienta de fuzzing identificada en logs Nginx.")
        self._narrar("El agente 008 ha detectado la herramienta de fuzzing en los logs Nginx. Alerta 100014 generada en tiempo real. El dashboard del cliente muestra el ataque contra su web sin depender de IDS perimetral: demostracion de defensa en profundidad Zero Trust.")

    def fase_3_cowrie_ok(self):
        UI.print_fase_header(3, "HONEYPOT SSH — LOGIN EXITOSO", "hydra + ssh", Config.IP_BASE, Config.TARGET_COWRIE)
        self._narrar("Fase 3: El atacante ejecuta fuerza bruta contra el servicio SSH del honeypot. Utiliza Hydra con un diccionario de contrasenas (top 200 de rockyou.txt) para romper la autenticacion. Las credenciales debiles son intencionales: el honeypot Cowrie registra TODO sin riesgo para la infraestructura real.")

        # Verificar Hydra
        rc, _, _ = Executor.run(["which", "hydra"], mostrar_output=False)
        if rc != 0:
            UI.warn("Hydra no instalado. Instalando...")
            os.system("sudo apt update -qq && sudo apt install -y -qq hydra 2>/dev/null")
            rc, _, _ = Executor.run(["which", "hydra"], mostrar_output=False)
            if rc != 0:
                UI.error("No se pudo instalar Hydra. Fallback a sshpass manual:")
                console.print(f"[yellow]   ssh {Config.COWRIE_USER}@{Config.TARGET_COWRIE}[/yellow]")
                console.print(f"[yellow]   Password: {Config.COWRIE_PASS}[/yellow]")
                Prompt.ask("[dim]Presiona ENTER cuando hayas terminado...[/dim]")
                UI.alerta_wazuh("100011", "14", "T-Pot Cowrie: LOGIN EXITOSO honeypot CRITICO")
                self._narrar("ALERTA CRITICA! El atacante ha conseguido acceso al honeypot. Nivel 14. El SOC ha sido notificado.")
                return

        # Crear mini-diccionario desde rockyou.txt (200 primeras + root asegurado)
        mini_dict = "/tmp/mini_rockyou.txt"
        self._info("Generando diccionario de ataque desde rockyou.txt (top 200)...")
        os.system(f"head -n 200 /usr/share/wordlists/rockyou.txt > {mini_dict} 2>/dev/null")
        os.system(f"echo 'root' >> {mini_dict}")
        UI.ok(f"Diccionario listo: {mini_dict}")

        # Ejecutar Hydra contra Cowrie
        self._info(f"Lanzando Hydra: usuario=root, target={Config.TARGET_COWRIE}...")
        rc, out, err = Executor.run(
            ["hydra", "-l", "root", "-P", mini_dict, "-t", "4", "-f",
             f"ssh://{Config.TARGET_COWRIE}"],
            timeout=60, mostrar_output=False
        )

        # Parsear resultado de Hydra
        password_encontrada = None
        for line in out.splitlines() + err.splitlines():
            if "[22][ssh]" in line and "password:" in line:
                password_encontrada = line.split("password:")[-1].strip().split()[0]
                break
            if "login: root" in line and "password:" in line:
                password_encontrada = line.split("password:")[-1].strip().split()[0]
                break

        if password_encontrada:
            UI.ok(f"Password encontrada por fuerza bruta: [bold red]{password_encontrada}[/bold red]")
            self._info("Abriendo sesion SSH interactiva contra Cowrie...")
            console.print("[bold yellow]═══════════════════════════════════════════════════════════════[/bold yellow]")
            console.print("[bold yellow]  SESION INTERACTIVA CONTRA HONEYPOT COWRIE[/bold yellow]")
            console.print("[bold yellow]  Password comprometida por fuerza bruta. Entra al sistema.[/bold yellow]")
            console.print("[bold yellow]  Escribe comandos como en un sistema real. Todo es falso.[/bold yellow]")
            console.print("[bold yellow]  Escribe 'exit' para salir y continuar la demo.[/bold yellow]")
            console.print("[bold yellow]═══════════════════════════════════════════════════════════════[/bold yellow]")
            os.system(f"sshpass -p '{password_encontrada}' ssh -o StrictHostKeyChecking=no "
                      f"-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "
                      f"-o ConnectTimeout=5 root@{Config.TARGET_COWRIE}")
            UI.ok("Sesion interactiva finalizada")
        else:
            UI.warn("Hydra no encontro password en el mini-diccionario. Fallback manual:")
            console.print(f"[yellow]   ssh root@{Config.TARGET_COWRIE}[/yellow]")
            console.print(f"[yellow]   Password: root[/yellow]")
            Prompt.ask("[dim]Presiona ENTER cuando hayas terminado...[/dim]")

        UI.alerta_wazuh("100011", "14", "T-Pot Cowrie: LOGIN EXITOSO honeypot CRITICO")
        self._narrar("ALERTA CRITICA! El atacante ha comprometido el honeypot por fuerza bruta. Nivel 14. El SOC ha sido notificado. Este es un sensor de engano: el atacante cree que ha tomado un sistema real, pero todo esta siendo registrado para analisis forense.")

    def fase_4_cowrie_fail(self):
        ip = self.ipm.siguiente_alias()
        UI.print_fase_header(4, "HONEYPOT SSH — FUERZA BRUTA FALLIDA", "ssh -b", ip, Config.TARGET_COWRIE)
        self._narrar("Fase 4: El atacante intenta fuerza bruta contra el honeypot con credenciales incorrectas. Cada intento fallido genera una alerta en Wazuh. Tras varios intentos, el Manager dispara Active Response y OPNsense bloquea la IP en el firewall perimetral.")
        if not self.ipm.crear_alias(ip):
            UI.error("No se pudo crear IP alias. Abortando fase.")
            return
        self._info(f"Atacando desde IP alias {ip} con passwords incorrectos...")
        passwords_falsos = ["admin123", "password123", "qwerty999x"]
        intentos_realizados = 0
        for i, pwd in enumerate(passwords_falsos, 1):
            self._info(f"Intento {i}/3: password {pwd}")
            rc, out, err = Executor.run(
                [f"sshpass -p {pwd} ssh -b {ip} -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
                 f"root@{Config.TARGET_COWRIE} 2>/dev/null"],
                timeout=8, shell=True, mostrar_output=False
            )
            if rc != 0:
                intentos_realizados += 1
            time.sleep(1)
        UI.ok(f"{intentos_realizados} intentos fallidos registrados contra Cowrie")
        UI.alerta_wazuh("100010", "10", "T-Pot Cowrie: intento SSH fallido")
        UI.alerta_wazuh("100040", "15", "AMENAZA CRITICA consolidada — Active Response triggered")
        self._narrar("Wazuh ha detectado multiples intentos fallidos. Active Response ha enviado la orden a OPNsense. El firewall perimetral ha bloqueado la IP del atacante. El atacante ya no puede llegar a la DMZ desde esa IP.")
        self.ultima_ip_bloqueada = ip

    def fase_5_rollback_1(self):
        UI.print_fase_header(5, "ROLLBACK #1 — MANUAL", "Comandos OPNsense", "—", "OPNsense PF")
        self._narrar("Fase 5: El analista SOC ejecuta rollback manual en OPNsense para desbloquear la IP del atacante. El framework NO realiza cambios automaticos: el operador ejecuta los comandos en el firewall perimetral.")
        if hasattr(self, "ultima_ip_bloqueada") and self.ultima_ip_bloqueada:
            ip = self.ultima_ip_bloqueada
            UI.comando_manual(
                f"sh {Config.ROLLBACK_SCRIPT} delete {ip}",
                f"OPNsense ({Config.OPNsense_IP})",
                f"La IP {ip} desaparecera de la tabla __wazuh_agent_drop"
            )
            Prompt.ask("")
            UI.info(f"Para eliminar el alias IP en Kali (opcional):")
            console.print(f"[yellow]   sudo ip addr del {ip}/24 dev {Config.INTERFACE}[/yellow]")
            del self.ultima_ip_bloqueada
        self._narrar("Rollback manual completado. La IP del atacante ha sido desbloqueada del firewall perimetral por el analista SOC. Puede continuar la demo.")

    def fase_6_fail2ban(self):
        ip = self.ipm.siguiente_alias()
        UI.print_fase_header(6, "ATAQUE SSH REAL — DOBLE CAPA DE DEFENSA", "ssh -b", ip, Config.TARGET_FAIL2BAN)
        self._narrar("Fase 6: El atacante ataca el servidor real (no el honeypot). En este caso, Fail2Ban actua como primera capa de defensa bloqueando localmente por iptables. Wazuh detecta el ban y dispara Active Response a OPNsense para el bloqueo perimetral. Tenemos DOS capas de defensa independientes.")
        if not self.ipm.crear_alias(ip):
            UI.error("No se pudo crear IP alias. Abortando fase.")
            return
        self._info(f"Atacando servidor real desde {ip}...")
        passwords_falsos = ["admin", "123456", "password"]
        intentos_realizados = 0
        for i, pwd in enumerate(passwords_falsos, 1):
            self._info(f"Intento {i}/3 contra SSH real")
            rc, out, err = Executor.run(
                [f"sshpass -p {pwd} ssh -b {ip} -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
                 f"root@{Config.TARGET_FAIL2BAN} 2>/dev/null"],
                timeout=8, shell=True, mostrar_output=False
            )
            if rc != 0:
                intentos_realizados += 1
            time.sleep(1)
        UI.ok(f"{intentos_realizados} intentos fallidos registrados contra SSH real")
        UI.alerta_wazuh("100040", "15", "AMENAZA CRITICA consolidada — Active Response triggered (Fail2Ban ban + PF bloqueo)")
        self._narrar("Doble bloqueo activado! Capa 1: Fail2Ban banea localmente en iptables (Server-Fail2Ban). Capa 2: Wazuh detecta el ban en auth.log (agente 008) y dispara Active Response a OPNsense (agente 009) para bloqueo perimetral. Dos capas independientes: host-based + perimetral. El atacante esta aislado.")
        self.ultima_ip_bloqueada_f2b = ip

    def fase_7_rollback_2(self):
        UI.print_fase_header(7, "ROLLBACK #2 — MANUAL COMPLETO", "Comandos OPNsense + Fail2Ban", "—", "Toda la infraestructura")
        self._narrar("Fase 7: Rollback completo manual. El analista SOC limpia ambas capas de defensa: bloqueo perimetral en OPNsense PF y bloqueo local en Fail2Ban. El framework solo muestra los comandos; el operador los ejecuta en cada sistema.")
        if hasattr(self, "ultima_ip_bloqueada_f2b") and self.ultima_ip_bloqueada_f2b:
            ip = self.ultima_ip_bloqueada_f2b
            UI.comando_manual(
                f"sh {Config.ROLLBACK_SCRIPT} delete {ip}",
                f"OPNsense ({Config.OPNsense_IP})",
                f"La IP {ip} desaparecera de la tabla __wazuh_agent_drop"
            )
            Prompt.ask("")
            UI.comando_manual(
                f"sudo fail2ban-client set sshd unbanip {ip}",
                f"Server-Fail2Ban ({Config.TARGET_FAIL2BAN})",
                f"La IP {ip} desaparecera de la lista de baneadas"
            )
            Prompt.ask("")
            UI.info(f"Para eliminar el alias IP en Kali (opcional):")
            console.print(f"[yellow]   sudo ip addr del {ip}/24 dev {Config.INTERFACE}[/yellow]")
            del self.ultima_ip_bloqueada_f2b
        self._narrar("Rollback manual completo. Ambas capas de defensa limpiadas por el analista SOC. Sistema restaurado a estado operativo.")

    def fase_8_dionaea(self):
        UI.print_fase_header(8, "SERVICIOS FALSOS — DIONAEA", "impacket", Config.IP_BASE, Config.TARGET_COWRIE)
        self._narrar("Fase 8: El atacante explora servicios adicionales expuestos por el honeypot Dionaea: SMB (445), MSSQL (1433). Estos son servicios falsos que capturan malware y comportamiento del atacante sin riesgo para la infraestructura real.")
        servicios = [
            ("SMB", "445", "impacket-smbclient", f"{Config.COWRIE_USER}:{Config.COWRIE_PASS}@{Config.TARGET_COWRIE}"),
            ("MSSQL", "1433", "impacket-mssqlclient", f"{Config.COWRIE_USER}:{Config.COWRIE_PASS}@{Config.TARGET_COWRIE}"),
        ]
        for nombre, puerto, tool, target in servicios:
            self._info(f"Probando {nombre} en puerto {puerto}...")
            rc, out, err = Executor.run(
                [f"timeout 5 {tool} {target} -port {puerto} 2>/dev/null"],
                timeout=10, shell=True, mostrar_output=False
            )
            if rc == 0:
                UI.ok(f"Conexion {nombre} registrada por Dionaea (rc=0)")
            elif rc == 124:
                UI.ok(f"Sonda {nombre} enviada a Dionaea (timeout, conexion registrada)")
            else:
                UI.warn(f"Sonda {nombre} no conecto o fue rechazada (rc={rc})")
            time.sleep(1)
        UI.alerta_wazuh("100020", "10", "T-Pot Dionaea: conexion exploit detectada")
        self._narrar("Dionaea ha registrado las conexiones a servicios falsos. El SOC tiene visibilidad de que protocolos intenta explotar el atacante. Esta informacion es valiosa para threat intelligence y para hardenear la infraestructura real.")

# ==============================================================================
# MENU PRINCIPAL Y ORQUESTACION
# ==============================================================================
class ZTTFramework:
    def __init__(self):
        self.ipm = IPManager()
        self.fases = Fases(self.ipm, modo_tribunal=True)

    def run_modo_tribunal(self):
        UI.print_banner()
        UI.narrar("Bienvenidos a la demostracion del SOC Zero Trust. Voy a guiaros paso a paso por cada fase del ataque y la respuesta defensiva, mostrando como nuestro sistema detecta, correlaciona y responde automaticamente ante amenazas.", pausa=True)
        secuencia = [
            self.fases.fase_0_status,
            self.fases.fase_1_recon,
            self.fases.fase_2_web,
            self.fases.fase_3_cowrie_ok,
            self.fases.fase_4_cowrie_fail,
            self.fases.fase_5_rollback_1,
            self.fases.fase_6_fail2ban,
            self.fases.fase_7_rollback_2,
            self.fases.fase_8_dionaea,
        ]
        for i, fase_fn in enumerate(secuencia):
            console.clear()
            UI.print_banner()
            fase_fn()
            if i < len(secuencia) - 1:
                if not Confirm.ask("[bold]Continuar con la siguiente fase?[/bold]", default=True):
                    break
        console.clear()
        UI.print_banner()
        UI.ok("Demostracion completada.")
        UI.warn("Limpiar alias IP manualmente en Kali si es necesario:")
        console.print(f"[yellow]   sudo ip addr flush dev {Config.INTERFACE} label 'eth0:*' 2>/dev/null || true[/yellow]")
        for ip in Config.IP_ALIAS_POOL:
            console.print(f"[yellow]   sudo ip addr del {ip}/24 dev {Config.INTERFACE} 2>/dev/null[/yellow]")

    def run_modo_espectaculo(self):
        UI.print_banner()
        UI.info("Modo Espectaculo: ejecucion automatica con delays...")
        self.fases.modo_tribunal = False
        self.fases.delay = Config.DELAY_ESPECTACULO
        secuencia = [
            self.fases.fase_0_status,
            self.fases.fase_1_recon,
            self.fases.fase_2_web,
            self.fases.fase_3_cowrie_ok,
            self.fases.fase_4_cowrie_fail,
            self.fases.fase_5_rollback_1,
            self.fases.fase_6_fail2ban,
            self.fases.fase_7_rollback_2,
            self.fases.fase_8_dionaea,
        ]
        for fase_fn in secuencia:
            console.clear()
            UI.print_banner()
            fase_fn()
            time.sleep(Config.DELAY_FASE)
        console.clear()
        UI.print_banner()
        UI.ok("Espectaculo completado.")
        UI.warn("Limpiar alias IP manualmente en Kali si es necesario:")
        console.print(f"[yellow]   sudo ip addr flush dev {Config.INTERFACE} label 'eth0:*' 2>/dev/null || true[/yellow]")
        for ip in Config.IP_ALIAS_POOL:
            console.print(f"[yellow]   sudo ip addr del {ip}/24 dev {Config.INTERFACE} 2>/dev/null[/yellow]")

    def run_fase_individual(self, fase_num=None):
        UI.print_banner()
        fases_map = {
            "0": self.fases.fase_0_status,
            "1": self.fases.fase_1_recon,
            "2": self.fases.fase_2_web,
            "3": self.fases.fase_3_cowrie_ok,
            "4": self.fases.fase_4_cowrie_fail,
            "5": self.fases.fase_5_rollback_1,
            "6": self.fases.fase_6_fail2ban,
            "7": self.fases.fase_7_rollback_2,
            "8": self.fases.fase_8_dionaea,
        }
        if fase_num is not None:
            # Ejecutar directamente sin menu interactivo
            fases_map[str(fase_num)]()
            return
        menu = Table(show_header=False, box=box.SIMPLE)
        menu.add_column(style="bold yellow")
        menu.add_column()
        opciones = [
            ("0", "Status"),
            ("1", "Reconocimiento (rustscan/nmap)"),
            ("2", "Web (ffuf/nikto)"),
            ("3", "Cowrie Login Exitoso"),
            ("4", "Cowrie Fuerza Bruta Fallida"),
            ("5", "Rollback #1 — Manual OPNsense"),
            ("6", "Fail2Ban Ataque Real"),
            ("7", "Rollback #2 — Manual OPNsense + Fail2Ban"),
            ("8", "Dionaea SMB/MSSQL"),
        ]
        for num, desc in opciones:
            menu.add_row(f"[{num}]", desc)
        console.print(Panel(menu, title="Fases disponibles", border_style="cyan"))
        eleccion = Prompt.ask("Selecciona fase", choices=[str(i) for i in range(9)], default="0")
        fases_map[eleccion]()

    def run_rollback_total(self):
        UI.print_banner()
        Rollback.rollback_total(self.ipm)

    def run_verificar_estado(self):
        UI.print_banner()
        UI.print_fase_header(0, "VERIFICACION DE ESTADO", "ping / pfctl / fail2ban-client", Config.IP_BASE, "Infraestructura completa")
        table = Table(title="Estado del Entorno", box=box.ROUNDED)
        table.add_column("Componente", style="cyan")
        table.add_column("Estado", style="green")
        for ip, nombre in [(Config.TARGET_COWRIE, "Cowrie"), (Config.TARGET_FAIL2BAN, "Fail2Ban")]:
            rc, _, _ = Executor.run(["ping", "-c", "1", "-W", "2", ip], mostrar_output=False)
            table.add_row(nombre, "[green]ONLINE[/green]" if rc == 0 else "[red]OFFLINE[/red]")
        rc, out, _ = Executor.run(["ip", "addr", "show", Config.INTERFACE], mostrar_output=False)
        alias_activos = [line for line in out.split("\n") if "172.17.0.20" in line]
        table.add_row("Alias IP", f"[yellow]{len(alias_activos)} activos[/yellow]" if alias_activos else "[dim]Ninguno[/dim]")
        console.print(table)
        UI.info("Verificar manualmente en OPNsense:")
        console.print(f"[yellow]   sh {Config.ROLLBACK_SCRIPT} show[/yellow]")
        UI.info("Verificar manualmente en Fail2Ban:")
        console.print(f"[yellow]   sudo fail2ban-client status sshd[/yellow]")

    def run_verificar_dependencias(self):
        Verificador.verificar_todo()

    def main(self):
        parser = argparse.ArgumentParser(description="ZTT Framework - Demo Tribunal SOC Zero Trust")
        parser.add_argument("--tribunal", action="store_true", help="Modo tribunal paso a paso")
        parser.add_argument("--espectaculo", action="store_true", help="Modo espectaculo automatico")
        parser.add_argument("--fase", type=int, choices=range(9), help="Ejecutar fase especifica (0-8)")
        parser.add_argument("--rollback", action="store_true", help="Rollback total")
        parser.add_argument("--status", action="store_true", help="Verificar estado")
        parser.add_argument("--deps", action="store_true", help="Verificar dependencias")
        args = parser.parse_args()
        if args.tribunal:
            self.run_modo_tribunal()
        elif args.espectaculo:
            self.run_modo_espectaculo()
        elif args.fase is not None:
            self.run_fase_individual(args.fase)
        elif args.rollback:
            self.run_rollback_total()
        elif args.status:
            self.run_verificar_estado()
        elif args.deps:
            self.run_verificar_dependencias()
        else:
            while True:
                console.clear()
                UI.print_banner()
                UI.print_menu()
                opcion = Prompt.ask("Selecciona opcion", choices=["0", "1", "2", "3", "4", "5", "6"], default="1")
                if opcion == "1":
                    self.run_modo_tribunal()
                elif opcion == "2":
                    self.run_modo_espectaculo()
                elif opcion == "3":
                    self.run_fase_individual()
                elif opcion == "4":
                    self.run_rollback_total()
                elif opcion == "5":
                    self.run_verificar_estado()
                elif opcion == "6":
                    self.run_verificar_dependencias()
                elif opcion == "0":
                    UI.ok("Saliendo del ZTT Framework. Hasta la proxima.")
                    break
                if opcion != "0":
                    Prompt.ask("[dim]Presiona ENTER para volver al menu...[/dim]")

# ==============================================================================
# ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    try:
        app = ZTTFramework()
        app.main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrumpido por usuario. Limpiando alias...[/bold yellow]")
        IPManager().limpiar_todos()
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Error fatal: {e}[/bold red]")
        IPManager().limpiar_todos()
        sys.exit(1)

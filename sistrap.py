import tkinter as tk
import subprocess
from scapy.all import ARP, Ether, srp
import time
import threading

class HackerConsoleApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NetHAck Console")
        self.root.configure(bg="black")  # Establece el color de fondo de la ventana

        # Configuración de la interfaz
        self.text_widget = tk.Text(root, bg="black", fg="green", font=("Courier", 12), padx=10, pady=10, borderwidth=2, relief="solid")
        self.text_widget.pack(expand=True, fill=tk.BOTH, padx=0, pady=(0, 10))  # Ajusta el padding para eliminar el margen blanco
        self.text_widget.config(state=tk.NORMAL)

        self.command_entry_frame = tk.Frame(root, bg="black")  # Añade un marco para la entrada de texto
        self.command_entry_frame.pack(fill=tk.X, padx=10, pady=10)  # Añade padding alrededor del marco

        self.command_entry = tk.Entry(self.command_entry_frame, bg="black", fg="green", font=("Courier", 12), borderwidth=2, relief="solid")
        self.command_entry.pack(fill=tk.X, padx=0, pady=0)  # Ajusta el padding del campo de entrada
        self.command_entry.bind('<Return>', self.execute_command)

        self.is_in_menu = True
        self.is_monitoring = False
        self.monitor_thread = None
        self.run_interface()

    def run_interface(self):
        """Función que muestra la interfaz ASCII de hacker"""
        if self.is_in_menu:
            banner = """
                .__  __                     
      ______ |__|/  |_____________  ______
     /  ___/ |  |   __\\_  __ \\__  \\ \\____ \\ 
     \\___ \\  |  |  |   |  | \\/ __ \\|  |_> >
    /____  > |__|__|   |__|  (____  /   __/ 
         \\/                       \\/|__|    
    """
            options = """
            [1] scannetwork   |       [2] monitordevice
               /\\             |          __|__
              /  \\            |          __|__|__|
              |__|            |         \\      /
             /____\\           |          ~~~~~~~
          ------------------------------------------  
            [3] show ssid      |       [4] Salir
               _____           |         
              /     \\          |      \\    /
             | () () |         |       Exit   
              \\  ^  /          |      /    \\ 
               ||||||
            """
            self.clear_text()
            self.text_widget.config(state=tk.NORMAL)
            self.text_widget.insert(tk.END, banner + options + "\n")
            self.text_widget.config(state=tk.DISABLED)
        else:
            self.clear_text()

    def clear_text(self):
        """Borra el texto en el widget de texto."""
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.delete(1.0, tk.END)
        self.text_widget.config(state=tk.DISABLED)

    def execute_command(self, event):
        """Ejecuta el comando basado en el texto ingresado"""
        command = self.command_entry.get()
        self.command_entry.delete(0, tk.END)  # Limpia la entrada después de ejecutar el comando

        if self.is_in_menu:
            if command.lower() == "action scannetwork":
                self.is_in_menu = False
                self.clear_text()
                self.scan_network()
            elif command.lower() == "action monitordevice":
                self.is_in_menu = False
                self.clear_text()
                self.start_monitoring()
            elif command.lower() == "action show ssid":
                self.is_in_menu = False
                self.clear_text()
                self.show_ssid()
            elif command.lower() == "action exit":
                self.quit()
            else:
                self.clear_text()
                self.text_widget.config(state=tk.NORMAL)
                self.text_widget.insert(tk.END, "\n[Error] Comando no reconocido.\n")
                self.text_widget.config(state=tk.DISABLED)
        else:
            if command.lower() == "leave":
                self.is_in_menu = True
                self.clear_text()
                self.run_interface()
            else:
                self.clear_text()
                self.text_widget.config(state=tk.NORMAL)
                self.text_widget.insert(tk.END, "\n[Error] Comando no reconocido.\n")
                self.text_widget.config(state=tk.DISABLED)

    def obtener_ssid(self):
        """Obtiene el SSID de la red Wi-Fi actual en Windows."""
        try:
            result = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], encoding="utf-8")
            for line in result.split('\n'):
                if "SSID" in line:
                    ssid = line.split(":")[1].strip()
                    return ssid
        except subprocess.CalledProcessError as e:
            self.text_widget.config(state=tk.NORMAL)
            self.text_widget.insert(tk.END, "\nError al ejecutar el comando: {}\n".format(e))
            self.text_widget.config(state=tk.DISABLED)
        except Exception as e:
            self.text_widget.config(state=tk.NORMAL)
            self.text_widget.insert(tk.END, "\nOcurrió un error: {}\n".format(str(e)))
            self.text_widget.config(state=tk.DISABLED)
        return "No disponible"

    def obtener_fabricante(self, mac):
        """Obtiene el fabricante basado en la dirección MAC."""
        oui_dict = {
            "74:e2:0c": "Apple",
            "d0:37:45": "Samsung",
            "5a:69:5c": "Huawei",
            "78:b4:6a": "Cisco",
            "d4:9d:c0": "HP",
            "d8:bf:ca": "Xiaomi",
            "d0:1f:17": "Xiaomi",
            "f4:ec:38": "Xiaomi",
            "e4:4f:5b": "Xiaomi",
            "2c:7f:32": "Xiaomi",
            "bc:ee:7b": "ASUS",
            "00:1a:2b": "Intel",
            "00:26:b9": "D-Link",
            "a4:50:46": "Tp-Link",
            "c8:d7:19": "LG",
            "3c:bd:3e": "Google",
            "b8:27:eb": "Raspberry Pi",
            "40:16:9f": "Motorola",
            "00:23:6c": "Netgear",
            "ec:8e:b5": "Lenovo",
            "00:1e:65": "Sony",
            "00:1b:77": "Panasonic",
            "58:9e:c6": "LG",
            "00:21:5d": "Dell",
            "a4:77:33": "Microsoft"
        }
        oui = mac.lower()[0:8]
        return oui_dict.get(oui, "Desconocido")

    def escanear_red(self, ip_rango):
        """Escanea la red local para identificar dispositivos conectados."""
        arp = ARP(pdst=ip_rango)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        try:
            result = srp(packet, timeout=3, verbose=0)[0]
        except Exception as e:
            self.text_widget.config(state=tk.NORMAL)
            self.text_widget.insert(tk.END, "\nError al escanear la red: {}\n".format(e))
            self.text_widget.config(state=tk.DISABLED)
            return []

        dispositivos = []
        for sent, received in result:
            fabricante = self.obtener_fabricante(received.hwsrc)
            dispositivos.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'fabricante': fabricante
            })

        return dispositivos

    def scan_network(self):
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, "\nEscaneando la red...\n")
        ip_rango = "192.168.1.1/24"  # Ajustar según la red
        dispositivos = self.escanear_red(ip_rango)
        for dispositivo in dispositivos:
            self.text_widget.insert(tk.END, f"IP: {dispositivo['ip']} MAC: {dispositivo['mac']} Fabricante: {dispositivo['fabricante']}\n")
        self.text_widget.config(state=tk.DISABLED)
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, "\nEscribe 'leave' para volver al menú.\n")
        self.text_widget.config(state=tk.DISABLED)

    def show_ssid(self):
        """Muestra el SSID de la red Wi-Fi actual"""
        ssid = self.obtener_ssid()
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, f"\nSSID Actual: {ssid}\n")
        self.text_widget.config(state=tk.DISABLED)
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, "\nEscribe 'leave' para volver al menú.\n")
        self.text_widget.config(state=tk.DISABLED)

    def start_monitoring(self):
        """Inicia el monitoreo de la red"""
        self.is_monitoring = True
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, "\nIniciando monitoreo...\n")
        self.text_widget.config(state=tk.DISABLED)

        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            self.monitor_thread = threading.Thread(target=self.monitor_red, daemon=True)
            self.monitor_thread.start()

    def monitor_red(self):
        """Monitorea la red para detectar cambios"""
        ip_rango = "192.168.1.1/24"  # Ajustar según la red
        while self.is_monitoring:
            self.text_widget.config(state=tk.NORMAL)
            self.text_widget.insert(tk.END, "\nMonitoreando...\n")
            self.text_widget.config(state=tk.DISABLED)
            dispositivos = self.escanear_red(ip_rango)
            self.text_widget.config(state=tk.NORMAL)
            for dispositivo in dispositivos:
                self.text_widget.insert(tk.END, f"IP: {dispositivo['ip']} MAC: {dispositivo['mac']} Fabricante: {dispositivo['fabricante']}\n")
            self.text_widget.config(state=tk.DISABLED)
            time.sleep(300)  # Esperar 5 minutos antes de escanear de nuevo

    def quit(self):
        """Sale de la aplicación y detiene el monitoreo"""
        self.is_monitoring = False
        self.root.quit()

# Crear la ventana principal y la aplicación
root = tk.Tk()
app = HackerConsoleApp(root)
root.mainloop()

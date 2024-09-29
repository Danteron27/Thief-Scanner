import tkinter as tk  # Librería para crear la interfaz gráfica
from tkinter import scrolledtext, ttk, messagebox  # Hace referencia al scroll en el apartado gráfico
import threading  # Permite la captura de paquetes
from scapy.all import sniff, IP, conf  # Librería para realizar la captura del tráfico de Red
import psutil  # Librería para traer el nombre del adaptador de Red (Ethernet, Wifi, Etc)

class PacketSniffer:
    def __init__(self, interface, alert_keywords, duration, app):
        self.interface = interface  # Interfaz de red seleccionada
        self.alert_keywords = alert_keywords
        self.duration = duration  # Duración del escaneo
        self.app = app
        self.packet_count = 0  # Variable para el conteo de paquetes
        self.alerts = 0  # Variable para el conteo de alertas
        self.common_ip = {}  # Array que almacena la IP más común

    def start_sniffing(self):  # Clase para iniciar la captura
        try:
            conf.L3socket = conf.L3socket  # Usar L3Socket para acceder a la capa 3
            sniff(iface=self.interface, prn=self.process_packet, timeout=self.duration * 60)
        except Exception as e:
            self.app.update_text(f"Error en la captura: {str(e)}")
        self.generate_summary()  # Al finalizar la consulta genera un resumen

    def process_packet(self, packet):  # Procesa cada paquete capturado con scapy
        self.packet_count += 1
        if IP in packet:
            ip_src = packet[IP].src
            self.app.update_text(f"Paquete capturado: {ip_src}")
            self.check_alerts(ip_src)
            self.track_ips(ip_src)

    def check_alerts(self, ip_src):  # Clase para el conteo de alertas
        if ip_src in self.alert_keywords:
            self.alerts += 1

    def track_ips(self, ip_src):  # Clase para el conteo de alertas más comunes
        if ip_src not in self.common_ip:
            self.common_ip[ip_src] = 1
        else:
            self.common_ip[ip_src] += 1

    def generate_summary(self):  # Clase para generar un resumen de la captura de tráfico de red.
        most_common_ip = max(self.common_ip, key=self.common_ip.get) if self.common_ip else "No hay datos"
        summary = (
            f"\nResumen del escaneo:\n"
            f"Total de paquetes capturados: {self.packet_count}\n"
            f"IP más común durante el escaneo: {most_common_ip}\n"
            f"Total de alertas generadas: {self.alerts}\n"
            f"Duración del escaneo: {self.duration} minutos\n"
            f"Estado general: {'Tráfico normal' if self.alerts == 0 else 'Se detectaron posibles anomalías'}\n"
        )
        self.app.update_text(summary)
        messagebox.showinfo("Resumen del Escaneo", summary)

    def stop_sniffing(self):  # Clase para detener el escaneo de red
        pass

class IDSApp:  # Esta clase maneja la creación de la interfaz gráfica de la red.
    def __init__(self, root):  # Define los parámetros de la interfaz
        self.root = root
        self.sniffer = None
        self.root.title("Sistema Detector de Intrusos")  # Define el título de la aplicación
        self.root.geometry("800x650")
        self.root.minsize(800, 650)  # Define el tamaño mínimo
        self.root.configure(bg="#2c3e50")  # Define el fondo

        # Esto asigna el título
        self.title_label = tk.Label(root, text="Sistema Detector de Intrusos (IDS)", font=("Helvetica", 18, "bold"), pady=10, bg="#2c3e50", fg="#ecf0f1")
        self.title_label.pack(fill=tk.X)

        # Esto permite scroll gracias a la librería
        self.text_area = scrolledtext.ScrolledText(root, width=80, height=20, font=("Courier", 12), bg="#34495e", fg="#ecf0f1", wrap=tk.WORD)
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Este es el contenedor inferior
        self.control_frame = tk.Frame(root, bg="#2c3e50")
        self.control_frame.pack(pady=10)

        # Apartado para escoger la interfaz de red
        self.interface_label = tk.Label(self.control_frame, text="Selecciona la interfaz de red:", font=("Helvetica", 14), bg="#2c3e50", fg="#ecf0f1")
        self.interface_label.pack(pady=5)

        self.interface_combo = ttk.Combobox(self.control_frame, values=self.get_network_interfaces(), font=("Helvetica", 12), state="readonly")
        self.interface_combo.set("Selecciona la interfaz")
        self.interface_combo.pack(pady=5)

        # Apartado para asignar el tiempo
        self.time_label = tk.Label(self.control_frame, text="Selecciona la duración del escaneo:", font=("Helvetica", 14), bg="#2c3e50", fg="#ecf0f1")
        self.time_label.pack(pady=5)

        self.time_combo = ttk.Combobox(self.control_frame, values=[1, 3, 5, 10, "Indefinido"], font=("Helvetica", 12), state="readonly")
        self.time_combo.set("Selecciona la duración")
        self.time_combo.pack(pady=5)

        self.button_frame = tk.Frame(self.control_frame, bg="#2c3e50")
        self.button_frame.pack(pady=10)
        # Botón iniciar tráfico
        self.start_button = tk.Button(self.button_frame, text="Iniciar Captura", command=self.start_sniffing, font=("Helvetica", 12), width=15, bg="#27ae60", fg="#ecf0f1", activebackground="#2ecc71")
        self.start_button.pack(side=tk.LEFT, padx=5)

        # Botón detener tráfico
        self.stop_button = tk.Button(self.button_frame, text="Detener Captura", command=self.stop_sniffing, font=("Helvetica", 12), width=15, bg="#e74c3c", fg="#ecf0f1", activebackground="#c0392b")
        self.stop_button.pack(side=tk.LEFT, padx=5)

    def update_text(self, message):  # Actualiza los paquetes rastreados en el log
        self.root.after(0, lambda: self.text_area.insert(tk.END, f"{message}\n"))
        self.root.after(0, lambda: self.text_area.yview(tk.END))

    def start_sniffing(self):  # Inicia el escaneo de red
        duration = self.time_combo.get()
        if duration == "Indefinido":
            duration = 0
        else:
            duration = int(duration)

        interface = self.interface_combo.get()  # Obtener la interfaz seleccionada
        alert_keywords = [""]  # Esto se encuentra en desarrollo por lo que todavía no está disponible al 100%

        self.text_area.insert(tk.END, "Iniciando captura...\n")
        self.sniffer = PacketSniffer(interface, alert_keywords, duration, self)
        threading.Thread(target=self.sniffer.start_sniffing).start()

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop_sniffing()
            self.text_area.insert(tk.END, "Deteniendo captura...\n")

    def get_network_interfaces(self):
        interfaces = psutil.net_if_addrs()
        return [iface for iface in interfaces]

if __name__ == "__main__":
    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()

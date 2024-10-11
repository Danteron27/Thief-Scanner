import datetime
from scapy.all import sniff, IP, TCP, conf
from tkinter import messagebox


class PacketSniffer:
    def __init__(self, interface, alert_keywords, duration, app, my_ip, monitored_ip):
        self.interface = interface
        self.alert_keywords = alert_keywords
        self.duration = duration
        self.packet_count = 0
        self.alerts = 0
        self.common_ip = {}
        self.logged_alerts = set()
        self.app = app
        self.my_ip = my_ip
        self.monitored_ip = monitored_ip

    def start_sniffing(self):
        try:
            conf.L3socket = conf.L3socket
            print(f"Comenzando a capturar en la interfaz: {self.interface}")  # Mensaje de depuración
            # Temporalmente sin filtro de tráfico TCP
            sniff(iface=self.interface, prn=self.process_packet, timeout=self.duration * 60)
        except Exception as e:
            self.app.update_text(f"Error en la captura: {str(e)}")
            messagebox.showerror("Error", f"Se produjo un error al iniciar la captura: {str(e)}")
            return
        self.generate_summary()

    def process_packet(self, packet):
        self.packet_count += 1
        formatted_packet = self.format_packet(packet)
        self.app.insert_packet(formatted_packet)

        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            tcp_flags = packet[TCP].flags

            # Mensaje de depuración para verificar IPs y flags
            print(f"Paquete procesado: {ip_src} -> {ip_dst} con flags: {tcp_flags}")

            # Detectar paquetes SYN
            if tcp_flags == 0x02:  # 0x02 representa el flag SYN
                # Temporalmente comentar la verificación de IP monitoreada
                print(f"Posible escaneo de puertos detectado desde: {ip_src}")  # Mensaje de depuración
                self.app.update_text(f"Posible escaneo de puertos detectado desde: {ip_src}")
                self.track_ips(ip_src)
                self.check_alerts(ip_src)

    def format_packet(self, packet):
        if IP in packet and TCP in packet:
            return (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport, packet[TCP].flags)
        return ("No disponible", "No disponible", "No disponible", "No disponible", "No disponible")

    def check_alerts(self, ip_src):
        if ip_src not in self.logged_alerts:
            self.alerts += 1
            self.logged_alerts.add(ip_src)
            self.log_alert(ip_src)

            self.app.packet_tree.insert("", "end", values=(ip_src, "N/A", "N/A", "N/A", "ALERTA"), tags=("alert",))
            self.app.packet_tree.tag_configure("alert", background="#e74c3c")

    def track_ips(self, ip_src):
        self.common_ip[ip_src] = self.common_ip.get(ip_src, 0) + 1

    def generate_summary(self):
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

    def log_alert(self, ip_src):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_message = f"[{timestamp}] ALERTA: Posible escaneo de puertos detectado desde {ip_src}\n"
        with open("alerts.log", "a") as log_file:
            log_file.write(alert_message)

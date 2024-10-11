import socket
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
import threading
from sniffer import PacketSniffer
from utils import get_network_interfaces
from tkinter import simpledialog

class IDSApp:
    def __init__(self, root):
        self.root = root
        self.sniffer = None
        self.root.title("Sistema Detector de Intrusos (IDS)")
        self.root.geometry("1000x900")
        self.root.minsize(1000, 900)  
        self.root.configure(bg="#1C2833")

        self.title_label = tk.Label(self.root, text="Sistema Detector de Intrusos (IDS)", font=("Montserrat", 28, "bold"), pady=10, bg="#1C2833", fg="#ECF0F1")
        self.title_label.pack(pady=20)

        self.text_area = scrolledtext.ScrolledText(root, width=80, height=10, font=("Courier New", 14), bg="#17202A", fg="#ECF0F1", wrap=tk.WORD, borderwidth=2, relief=tk.FLAT)
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.tree_frame = tk.Frame(root, bg="#17202A", bd=2, relief=tk.GROOVE)
        self.tree_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Creación del Treeview con Scrollbar
        self.packet_tree = ttk.Treeview(self.tree_frame, columns=("IP Origen", "Puerto Origen", "IP Destino", "Puerto Destino", "Flags"), show='headings', height=15)
        self.packet_tree.heading("IP Origen", text="IP Origen")
        self.packet_tree.heading("Puerto Origen", text="Puerto Origen")
        self.packet_tree.heading("IP Destino", text="IP Destino")
        self.packet_tree.heading("Puerto Destino", text="Puerto Destino")
        self.packet_tree.heading("Flags", text="Flags")
        self.packet_tree.column("#1", minwidth=100, width=150)  # Ajuste del ancho mínimo de la columna
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar vertical, más visible y con grosor
        style = ttk.Style()
        style.configure("Vertical.TScrollbar", gripcount=0,
                        background="#95a5a6", darkcolor="#7f8c8d", lightcolor="#bdc3c7",
                        troughcolor="#34495e", bordercolor="#2c3e50", arrowcolor="#ecf0f1", relief=tk.SOLID)

        self.scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.packet_tree.yview, style="Vertical.TScrollbar")
        self.scrollbar.pack(side=tk.RIGHT, fill='y', padx=5)

        self.packet_tree.configure(yscrollcommand=self.scrollbar.set)

        self.control_frame = tk.Frame(root, bg="#1C2833")
        self.control_frame.pack(pady=10)

        self.interface_label = tk.Label(self.control_frame, text="Selecciona la interfaz de red:", font=("Montserrat", 14), bg="#1C2833", fg="#ECF0F1")
        self.interface_label.pack(pady=5)

        self.interface_combo = ttk.Combobox(self.control_frame, values=get_network_interfaces(), font=("Montserrat", 12), state="readonly")
        self.interface_combo.set("Selecciona la interfaz")
        self.interface_combo.pack(pady=5)

        self.time_label = tk.Label(self.control_frame, text="Selecciona la duración del escaneo:", font=("Montserrat", 14), bg="#1C2833", fg="#ECF0F1")
        self.time_label.pack(pady=5)

        self.time_combo = ttk.Combobox(self.control_frame, values=[1, 3, 5, 10, 60], font=("Montserrat", 12), state="readonly")
        self.time_combo.set("Selecciona la duración")
        self.time_combo.pack(pady=5)

        self.start_button = tk.Button(self.control_frame, text="Iniciar Captura", command=self.start_capture, font=("Montserrat", 14), bg="#2ECC71", fg="#ECF0F1", activebackground="#27AE60", relief=tk.FLAT)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(self.control_frame, text="Detener Captura", command=self.stop_capture, font=("Montserrat", 14), bg="#E74C3C", fg="#ECF0F1", activebackground="#C0392B", relief=tk.FLAT)
        self.stop_button.pack(side=tk.LEFT, padx=5)

    def update_text(self, message):
        self.text_area.insert(tk.END, f"{message}\n")
        self.text_area.see(tk.END)

    def insert_packet(self, packet):
        self.packet_tree.insert("", tk.END, values=packet)

    def start_capture(self):
        interface = self.interface_combo.get()
        duration = self.time_combo.get()
        monitored_ip = self.get_monitored_ip()
        my_ip = socket.gethostbyname(socket.gethostname())
        alert_keywords = ""

        # Verificar que se haya seleccionado la interfaz y la duración
        if not interface or interface == "Selecciona la interfaz":
            messagebox.showerror("Error", "Por favor, seleccione la interfaz de red.")
            return
        if not duration:
            messagebox.showerror("Error", "Por favor, seleccione la duración del escaneo.")
            return

        duration = int(duration)  # Convertir la duración a un entero

        # Iniciar el sniffer en un hilo separado
        self.sniffer = PacketSniffer(interface, alert_keywords, duration, self, my_ip, monitored_ip)
        threading.Thread(target=self.sniffer.start_sniffing, daemon=True).start()
        self.update_text(f"Iniciando captura en la interfaz: {interface} por {duration} minutos.")

    def stop_capture(self):
        if self.sniffer:
            self.sniffer.stop_sniffing()
            self.update_text("Captura detenida.")

    def get_monitored_ip(self):
        ip = simpledialog.askstring("IP a Monitorear", "Ingrese la IP a monitorear:", parent=self.root)
        return ip if ip else ""

if __name__ == "__main__":
    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()

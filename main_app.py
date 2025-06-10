import tkinter as tk
import socket
import os
from tkinter import filedialog, messagebox 
from tkinter import scrolledtext
from tkinter import ttk
from threading import Thread
import hashlib
import struct



class UDPApp:
    def __init__(self, window):
        self.window = window
        self.window.title("UDP")
        self.window.geometry("500x600")
        self.window.configure(bg="#f0f0f0")
        self.setup_gui()

    def setup_gui(self):
        title = tk.Label(self.window, text="UDP File Transfer Tool", font=("Helvetica", 18, "bold"), fg="white", bg="#333")
        title.pack(fill="x", pady=10)

        form_frame = tk.Frame(self.window, padx=20, pady=10)
        form_frame.pack(fill="both")
        
        frame = ttk.LabelFrame(window, text="Transfer Info : ", padding=10)
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        tk.Label(form_frame, text="Select File:", font=("Arial", 12)).grid(row=0, column=0, sticky="e", pady=5)
        self.entry_file = tk.Entry(form_frame, width=40)
        self.entry_file.grid(row=0, column=1, pady=5)
        tk.Button(form_frame, text="Browse", command=self.select_file, bg="#4CAF50", fg="white").grid(row=0, column=2, padx=5)

        tk.Label(form_frame, text="Receiver IP:", font=("Arial", 12)).grid(row=1, column=0, sticky="e", pady=5)
        self.entry_ip = tk.Entry(form_frame)
        self.entry_ip.grid(row=1, column=1, pady=5)
        self.entry_ip.insert(0, "192.168.245.224")

        tk.Label(form_frame, text="Port:", font=("Arial", 12)).grid(row=2, column=0, sticky="e", pady=5)
        self.port_entry = tk.Entry(form_frame)
        self.port_entry.grid(row=2, column=1, pady=5)
        self.port_entry.insert(0, "5001")

        self.preview_label = tk.Label(frame, text="No file selected", font=("Arial", 10), fg="gray")
        self.preview_label.pack(pady=5)

        button_frame = tk.Frame(self.window, pady=10)
        button_frame.pack()

        tk.Button(button_frame, text="Send File", command=self.on_send_click, width=20, bg="#2196F3", fg="white").grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="Receive File", command=self.on_receive_click, width=20, bg="#FF5722", fg="white").grid(row=0, column=1, padx=10)

       
        
        # Scrollable frame using canvas
        canvas = tk.Canvas(self.window, height=200)
        scroll_frame = ttk.LabelFrame(canvas, text="Transfer Info :", padding=10)
        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        # Vertical scrollbar
        vsb = tk.Scrollbar(self.window, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)

        # Horizontal scrollbar
        hsb = tk.Scrollbar(self.window, orient="horizontal", command=canvas.xview)
        canvas.configure(xscrollcommand=hsb.set)

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        canvas.pack(side="left", fill="both", expand=True)

        # Put the frame inside the canvas
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")

        self.status_label = tk.Label(scroll_frame, text="Status: Ready", font=("Arial", 10), fg="blue")
        self.status_label.pack(pady=10)
        
        self.progress_bar = ttk.Progressbar(scroll_frame, orient="horizontal", length=400, mode="determinate")
        self.progress_bar.pack(pady=10)
    
    
    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.entry_file.delete(0, tk.END)
            self.entry_file.insert(0, file_path)
            file_name = os.path.basename(file_path)
            file_size = round(os.path.getsize(file_path) / (1024 * 1024), 2)
            self.preview_label.config(text=f"Selected: {file_name}\nSize: {file_size} MB", fg="green")

    def update_status(self, message, progress=None):
        self.status_label.config(text=message)
        if progress is not None:
            self.progress_bar["value"] = progress
        self.window.update()
    
    
    def log_error(self, error_msg):
        with open("error_log.txt", "a") as log_file:
            log_file.write(f"{error_msg}\n")
        print(f"Error: {error_msg}")
    
    def validate_ip_port(self, ip, port):
        try:
            socket.inet_aton(ip)
            port = int(port)
            return True, port
        except:
            return False, None

    def create_udp_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10.0)
        return sock
    
    def packet_to_chunk(self, packet):
        if len(packet)<4:
            return None, None
        seq_num = struct.unpack("!I", packet[:4])[0]
        chunk = packet[4:]
        return seq_num , chunk

    
    def chunk_to_packet(self, seq_num, chunk):
        header = struct.pack("!I", seq_num)
        return header + chunk
    
    def validate_ack(self, ack_packet, expected_seq):
        try:
            return ack_packet.decode() == f"ACK:{expected_seq}"
        except UnicodeDecodeError:
            return False

    def send_chunk(self, sock, chunk, seq_num, receiver_ip, receiver_port, max_retries=3):
        packet = self.chunk_to_packet(seq_num, chunk)
        for attempt in range(max_retries):
            try:
                sock.sendto(packet, (receiver_ip, receiver_port))
                self.update_status(f"Sending chunk {seq_num} (Attempt {attempt + 1}/{max_retries})")
                ack, _ = sock.recvfrom(5000)
                if self.validate_ack(ack, seq_num):
                    return True
            except (socket.timeout, ConnectionResetError) as e:
                self.log_error(f"Error on chunk {seq_num}, attempt {attempt + 1}: {e}")
                continue
        return False

    def receive_chunk(self, sock):
        try:
            data, addr = sock.recvfrom(5000)
            seq_num, chunk = self.packet_to_chunk(data)
            if seq_num is not None:
                sock.sendto(f"ACK:{seq_num}".encode(), addr)
                return seq_num, chunk, addr
            self.log_error("Invalid packet received")
            return None, None, None
        except socket.timeout:
            self.log_error("No chunk received (timeout)")
            return None, None, None
    
    def send_file(self, file_path, receiver_ip, port):
        sock = self.create_udp_socket()
        failed_chunks = []

        for seq_num, chunk in enumerate(self.split_file(file_path)):
            print(f"Sending chunk {seq_num}, size: {len(chunk)}")
            if not self.send_chunk(sock, chunk, seq_num, receiver_ip, port):
                failed_chunks.append(seq_num)


        sock.close()
        if failed_chunks:
            self.update_status(f"Failed chunks: {failed_chunks}")
        else:
            self.update_status("File sent successfully!")

    def receive_file(self, save_path, port):
        if not save_path:
            self.update_status("Error: No save location selected")
            messagebox.showerror("Error", "Select a save location!")
            return
        if not self.validate_ip_port("0.0.0.0", port)[0]:
            self.update_status("Error: Invalid port")
            messagebox.showerror("Error", "Invalid port")
            return
        port = int(port)
        dest_folder = os.path.dirname(save_path)
        if dest_folder:
            try:
                os.makedirs(dest_folder, exist_ok=True)
            except OSError as e:
                self.log_error(f"Error creating directory {dest_folder}: {e}")
                self.update_status("Error: Cannot create destination folder")
                messagebox.showerror("Error", f"Cannot create folder: {e}")
                return
        sock = self.create_udp_socket()
        try:
            sock.bind(("0.0.0.0", port))
            self.update_status(f"Listening on port {port}...", 0)
            self.progress_bar["value"] = 0  # Reset progress bar
        except OSError as e:
            self.log_error(f"Error binding to port {port}: {e}")
            self.update_status(f"Error: Cannot bind to port {port}")
            messagebox.showerror("Error", f"Cannot bind to port: {e}")
            return
        chunks = {}
        max_chunks = 10000
        while len(chunks) < max_chunks:
            seq_num, chunk, addr = self.receive_chunk(sock)
            if seq_num is None:
                print("No chunk received")
                continue
            chunks[seq_num] = chunk
            progress = min((len(chunks) / max_chunks) * 100, 100)

            self.update_status(f"Received chunk {seq_num} from {addr[0]}", progress)
            
        sock.close()
        if chunks:
            try:
                self.reassemble_file(chunks, save_path)
                received_checksum = self.generate_checksum(save_path)
                self.update_status(f"File saved as {os.path.basename(save_path)}\nChecksum: {received_checksum[:8]}...", 100)
                messagebox.showinfo("Success", "File received successfully!")
            except OSError as e:
                self.log_error(f"Error saving file {save_path}: {e}")
                self.update_status("Error: Cannot save file")
                messagebox.showerror("Error", f"Cannot save file: {e}")
        else:
            self.update_status("No file received", 0)
            messagebox.showwarning("Warning", "No file received")

    def split_file(self, file_path, chunk_size=2048):
        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    def reassemble_file(self, chunks, output_path):
        with open(output_path, 'wb') as file:
            for seq_num in sorted(chunks.keys()):
                file.write(chunks[seq_num])

    def generate_checksum(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(1024), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def on_send_click(self):
        file_path = self.entry_file.get()
        ip = self.entry_ip.get()
        port = self.port_entry.get()
        Thread(target=self.send_file, args=(file_path, ip, int(port))).start()

    def _threaded_receive_file(self):
        port = self.port_entry.get().strip()
        selected_folder = filedialog.askdirectory(title="Select Folder to Save File")
        if selected_folder:
            save_path = os.path.join(selected_folder, "received_file.bin")
            self.receive_file(save_path, port)

    def on_receive_click(self):
        Thread(target=self._threaded_receive_file).start()



    def on_closing(self):
        self.window.destroy()


if __name__ == "__main__":
    window = tk.Tk()
    app = UDPApp(window)
    window.protocol("WM_DELETE_WINDOW", app.on_closing)
    window.mainloop()

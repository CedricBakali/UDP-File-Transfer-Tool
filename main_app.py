import tkinter as tk
import socket
import os
from tkinter import filedialog, messagebox 
from tkinter import ttk
from threading import Thread
import hashlib


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
        self.entry_ip.insert(0, "127.0.0.1")

        tk.Label(form_frame, text="Port:", font=("Arial", 12)).grid(row=2, column=0, sticky="e", pady=5)
        self.port_entry = tk.Entry(form_frame)
        self.port_entry.grid(row=2, column=1, pady=5)
        self.port_entry.insert(0, "5000")

        self.preview_label = tk.Label(frame, text="No file selected", font=("Arial", 10), fg="gray")
        self.preview_label.pack(pady=5)

        button_frame = tk.Frame(self.window, pady=10)
        button_frame.pack()

        tk.Button(button_frame, text="Send File", command=self.on_send_click, width=20, bg="#2196F3", fg="white").grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="Receive File", command=self.on_receive_click, width=20, bg="#FF5722", fg="white").grid(row=0, column=1, padx=10)

        self.status_label = tk.Label(frame, text="Status: Ready", font=("Arial", 10), fg="blue")
        self.status_label.pack(pady=10)

    
    
    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.entry_file.delete(0, tk.END)
            self.entry_file.insert(0, file_path)
            file_name = os.path.basename(file_path)
            file_size = round(os.path.getsize(file_path) / (1024 * 1024), 2)
            self.preview_label.config(text=f"Selected: {file_name}\nSize: {file_size} MB", fg="green")

    def update_status(self, message):
        self.status_label.config(text=message)
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
        sock.settimeout(3.0)
        return sock
    
    def packet_to_chunk(self, packet):
        try:
            seq_num, chunk = packet.split(b':', 1)
            return int(seq_num), chunk
        except ValueError:
            return None, None
    
    def chunk_to_packet(self, seq_num, chunk):
        return f"{seq_num}:".encode() + chunk

    def send_chunk(self, sock, chunk, seq_num, receiver_ip, receiver_port, max_retries=3):
        packet = self.chunk_to_packet(seq_num, chunk)
        for attempt in range(max_retries):
            try:
                sock.sendto(packet, (receiver_ip, receiver_port))
                self.update_status(f"Sending chunk {seq_num} (Attempt {attempt + 1}/{max_retries})")
                ack, _ = sock.recvfrom(1024)  # Line 84
                if self.validate_ack(ack, seq_num):
                    return True
            except (socket.timeout, ConnectionResetError) as e:  # Add ConnectionResetError
                self.log_error(f"Error on chunk {seq_num}, attempt {attempt + 1}: {e}")
                continue
        return False

    def receive_chunk(self, sock):
        try:
            data, addr = sock.recvfrom(1024)
            seq_num, chunk = self.packet_to_chunk(data)
            if seq_num is not None:
                sock.sendto(f"ACK:{seq_num}".encode(), addr)
                self.update_status(f"Received chunk {seq_num} from {addr[0]}", (len(chunks) / 10000) * 100)
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
        if not self.validate_ip_port("0.0.0.0", port)[0]:
            self.update_status("Error: Invalid port")
            messagebox.showerror("Error", "Invalid port")
            return

        # Create destination folder if it doesn't exist
        dest_folder = os.path.dirname(save_path)
        if dest_folder:  # Only create if a directory is specified
            try:
                os.makedirs(dest_folder, exist_ok=True)
            except OSError as e:
                self.log_error(f"Error creating directory {dest_folder}: {e}")
                self.update_status("Error: Cannot create destination folder")
                messagebox.showerror("Error", f"Cannot create folder: {e}")
                return
        
        
        port = int(port)
        sock = self.create_udp_socket()
        sock.bind(("0.0.0.0", port))
        chunks = {}
        self.update_status(f"Listening on port {port}...")
        print(f"Waiting on port {port}...")  # Confirm it's listening


        while len(chunks) < 10000:
            seq_num, chunk, addr = self.receive_chunk(sock)
            if seq_num is None:
                print("No chunk received")
                continue
            print(f"Received chunk {seq_num} from {addr}")
            chunks[seq_num] = chunk

            sock.settimeout(5.0)
            try:
                sock.recvfrom(1024)
            except socket.timeout:
                break

        sock.close()
        if chunks:
            self.reassemble_file(chunks, save_path)
            received_checksum = self.generate_checksum(save_path)
            self.update_status(f"File saved as {os.path.basename(save_path)}\nChecksum: {received_checksum[:8]}...")
            messagebox.showinfo("Success", "File received successfully!")
        else:
            self.update_status("No file received")
            messagebox.showwarning("Warning", "No file received")

    def split_file(self, file_path, chunk_size=1024):
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
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def on_send_click(self):
        file_path = self.entry_file.get()
        ip = self.entry_ip.get()
        port = self.port_entry.get()
        Thread(target=self.send_file, args=(file_path, ip, int(port))).start()

    def _threaded_receive_file(self):
        port = self.port_entry.get().strip()
        save_path = filedialog.asksaveasfilename(defaultextension=".bin", title="Select Save Location")
        if save_path:
            self.receive_file(save_path, port)

    def on_receive_click(self):
        save_path = filedialog.asksaveasfilename()
        port = self.port_entry.get()
        Thread(target=self.receive_file, args=(save_path, port)).start()


    def on_closing(self):
        self.window.destroy()


if __name__ == "__main__":
    window = tk.Tk()
    app = UDPApp(window)
    window.protocol("WM_DELETE_WINDOW", app.on_closing)
    window.mainloop()

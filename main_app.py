import tkinter as tk
import socket
import os
import struct
import math
import json
from tkinter import filedialog, messagebox, scrolledtext, ttk
from threading import Thread


PACKET_BUFFER_SIZE = 1472  # this is the best and common UDP payload size, it will enhance the UDP unreliability
DATA_CHUNK_SIZE = 1024  # this is the size of the piece in each packet
RECEIVER_IP = '0.0.0.0'  # this IP address helps to listen for all available interfaces
DEFAULT_PORT = 5001
SENDER_TIMEOUT_S = 2.0  # 2 seconds for the sender to wait for the acknowledgemnt rfom the receiver
RECEIVER_TIMEOUT_S = 10.0  # the receiver will be giving up when the packet has not arrived in 10 secs

# these are the protocol headers that will be using simple byte strings to identify packets types when sending and recieving
META_HEADER = b'META'
DATA_HEADER = b'DATA'
EOF_HEADER = b'EOF'
ACK_HEADER = b'ACK'


class UDPApp:
    def __init__(self, window):
        self.window = window
        self.window.title("UDP")
        self.window.geometry("500x600")
        self.window.configure(bg="#f0f0f0")
        self.setup_gui()
        self.sock = None  # this will hold the socket object

    def setup_gui(self):
        title = tk.Label(self.window, text="UDP File Transfer Tool", font=("Helvetica", 18, "bold"), fg="white",
                         bg="#333")
        title.pack(fill="x", pady=10)

        form_frame = tk.Frame(self.window, padx=20, pady=10)
        form_frame.pack(fill="both")

        frame = ttk.LabelFrame(self.window, text="Transfer Info : ", padding=10)
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        tk.Label(form_frame, text="Select File:", font=("Arial", 12)).grid(row=0, column=0, sticky="e", pady=5)
        self.entry_file = tk.Entry(form_frame, width=40)
        self.entry_file.grid(row=0, column=1, pady=5)
        tk.Button(form_frame, text="Browse", command=self.select_file, bg="#4CAF50", fg="white").grid(row=0, column=2,
                                                                                                      padx=5)

        tk.Label(form_frame, text="Receiver IP:", font=("Arial", 12)).grid(row=1, column=0, sticky="e", pady=5)
        self.entry_ip = tk.Entry(form_frame)
        self.entry_ip.grid(row=1, column=1, pady=5)
        self.entry_ip.insert(0, "0.0.0.0")

        tk.Label(form_frame, text="Port:", font=("Arial", 12)).grid(row=2, column=0, sticky="e", pady=5)
        self.port_entry = tk.Entry(form_frame)
        self.port_entry.grid(row=2, column=1, pady=5)
        self.port_entry.insert(0, str(DEFAULT_PORT))

        self.preview_label = tk.Label(frame, text="No file selected", font=("Arial", 10), fg="gray")
        self.preview_label.pack(pady=5)

        button_frame = tk.Frame(self.window, pady=10)
        button_frame.pack()

        self.send_button = tk.Button(button_frame, text="Send File", command=self.on_send_click, width=20, bg="#2196F3",fg="white")
        self.send_button.grid(row=0, column=0, padx=10)

        self.receive_button = tk.Button(button_frame, text="Receive File", command=self.on_receive_click, width=20,bg="#FF5722", fg="white")
        self.receive_button.grid(row=0, column=1, padx=10)

        # using simple status frame
        status_container = ttk.LabelFrame(self.window, text="Transfer Status", padding=10)
        status_container.pack(padx=10, pady=10, fill="both", expand=True)

        self.status_label = tk.Label(status_container, text="Status: Ready", font=("Arial", 10), fg="blue", anchor='w')
        self.status_label.pack(pady=5, fill='x')

        self.progress_bar = ttk.Progressbar(status_container, orient="horizontal", length=400, mode="determinate")
        self.progress_bar.pack(pady=10, fill='x')

    def update_ui_state(self, is_active):
        #disable/enable ui element during transferring
        state = tk.DISABLED if is_active else tk.NORMAL
        self.send_button.config(state=state)
        self.receive_button.config(state=state)
        for child in self.window.winfo_children():
            if isinstance(child, tk.Frame):
                for widget in child.winfo_children():
                    if isinstance(widget, (tk.Entry, tk.Button)) and widget not in [self.send_button,self.receive_button]:widget.config(state=state)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.entry_file.delete(0, tk.END)
            self.entry_file.insert(0, file_path)
            file_name = os.path.basename(file_path)
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            self.preview_label.config(text=f"Selected: {file_name}\nSize: {file_size_mb:.2f} MB", fg="green")

    def update_status(self, message, progress=None):
        def _update():
            self.status_label.config(text=message)
            if progress is not None:
                self.progress_bar["value"] = progress
            self.window.update_idletasks()

        # updates must be made after the main thread
        self.window.after(0, _update)

    def on_send_click(self):
        file_path = self.entry_file.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file to send.")
            return

        receiver_ip = self.entry_ip.get()
        try:
            port = int(self.port_entry.get())
            if not (1024 < port < 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Invalid Port. Must be a number between 1025 and 65534.")
            return

        # disabling the UI and start the send thread
        self.update_ui_state(is_active=True)
        Thread(target=self.send_file_threaded, args=(file_path, receiver_ip, port), daemon=True).start()

    def on_receive_click(self):
        try:
            port = int(self.port_entry.get())
            if not (1024 < port < 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Invalid Port. Must be a number between 1025 and 65534.")
            return

        save_dir = filedialog.askdirectory(title="Select Folder to Save Received File")
        if not save_dir:
            return

        # disabling the UI and start the receive thread
        self.update_ui_state(is_active=True)
        Thread(target=self.receive_file_threaded, args=(port, save_dir), daemon=True).start()

    def send_with_retry(self, sock, data, addr, expected_ack, max_retries=5):
        #send packets and wait for acknowledgements
        for attempt in range(max_retries):
            try:
                sock.sendto(data, addr)
                ack_packet, _ = sock.recvfrom(PACKET_BUFFER_SIZE)
                if ack_packet == expected_ack:
                    return True
                else:
                    self.update_status(f"Warning: Received wrong ACK. Retrying... (Attempt {attempt + 1})")
            except socket.timeout:
                self.update_status(f"Warning: ACK timeout. Retrying... (Attempt {attempt + 1})")
        return False

    def send_file_threaded(self, file_path, receiver_ip, port):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(SENDER_TIMEOUT_S)

            filename = os.path.basename(file_path)
            filesize = os.path.getsize(file_path)
            total_chunks = math.ceil(filesize / DATA_CHUNK_SIZE)

            self.update_status(f"Contacting receiver at {receiver_ip}:{port}...")

            # sending metadata
            metadata = {'filename': filename, 'filesize': filesize, 'total_chunks': total_chunks}
            meta_packet = META_HEADER + json.dumps(metadata).encode('utf-8')

            if not self.send_with_retry(self.sock, meta_packet, (receiver_ip, port), ACK_HEADER + META_HEADER):
                raise ConnectionError("Receiver did not acknowledge metadata. Aborting.")

            # sending file data
            self.update_status(f"Starting file transfer of '{filename}'...")
            with open(file_path, 'rb') as f:
                for seq_num in range(total_chunks):
                    chunk = f.read(DATA_CHUNK_SIZE)
                    # packet format: DATA_HEADER | seq_num (4 bytes) | chunk_data
                    packet = DATA_HEADER + struct.pack('!I', seq_num) + chunk

                    # expected acknowledegements with the format: ack header | sequence number in 4 bytes
                    expected_ack = ACK_HEADER + struct.pack('!I', seq_num)

                    if not self.send_with_retry(self.sock, packet, (receiver_ip, port), expected_ack):
                        raise ConnectionError(f"Failed to get ACK for chunk {seq_num}. Aborting.")

                    progress = (seq_num + 1) / total_chunks * 100
                    self.update_status(f"Sending chunk {seq_num + 1}/{total_chunks}...", progress)

            # sending the End Of File Marker to the receiver
            self.update_status("Finalizing transfer...")
            if not self.send_with_retry(self.sock, EOF_HEADER, (receiver_ip, port), ACK_HEADER + EOF_HEADER):
                raise ConnectionError("Receiver did not acknowledge EOF. Transfer may be incomplete.")

            self.update_status(f"File '{filename}' sent successfully!", 100)
            messagebox.showinfo("Success", "File transfer complete.")

        except Exception as e:
            self.update_status(f"Error: {e}", 0)
            messagebox.showerror("Transfer Failed", f"An error occurred: {e}")
        finally:
            if self.sock:
                self.sock.close()
            self.update_ui_state(is_active=False)

    def receive_file_threaded(self, port, save_dir):
        chunks = {}
        metadata = None
        sender_addr = None

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((RECEIVER_IP, port))
            self.update_status(f"Listening on port {port}...")

            # receiving metadata
            self.sock.settimeout(None)  # waiting for no timeout for the first data
            meta_packet, sender_addr = self.sock.recvfrom(PACKET_BUFFER_SIZE)

            if not meta_packet.startswith(META_HEADER):
                raise ConnectionError("Received invalid first packet. Not metadata.")

            metadata = json.loads(meta_packet[len(META_HEADER):].decode('utf-8'))
            total_chunks = metadata['total_chunks']
            filename = metadata['filename']
            save_path = os.path.join(save_dir, filename)

            self.update_status(f"Receiving '{filename}' ({total_chunks} chunks) from {sender_addr[0]}...")
            self.sock.sendto(ACK_HEADER + META_HEADER, sender_addr)  # acknowledgements for metadata

            # start receieving file data
            self.sock.settimeout(RECEIVER_TIMEOUT_S)  # setting timeouts for packets

            while len(chunks) < total_chunks:
                packet, addr = self.sock.recvfrom(PACKET_BUFFER_SIZE)

                if addr != sender_addr: continue  # for security reasons, this line will be ignoring packets from other sources

                if packet.startswith(DATA_HEADER):
                    header = packet[:len(DATA_HEADER) + 4]
                    data = packet[len(DATA_HEADER) + 4:]
                    seq_num = struct.unpack('!I', header[len(DATA_HEADER):])[0]

                    if seq_num not in chunks:
                        chunks[seq_num] = data
                        progress = len(chunks) / total_chunks * 100
                        self.update_status(f"Received chunk {seq_num + 1}/{total_chunks}...", progress)

                    # this part will be sending acknowledgements to the sender to make sure each chunk sent has been received even with duplicated chunks
                    ack_packet = ACK_HEADER + struct.pack('!I', seq_num)
                    self.sock.sendto(ack_packet, sender_addr)

                elif packet == EOF_HEADER:
                    self.update_status("EOF signal received.")
                    self.sock.sendto(ACK_HEADER + EOF_HEADER, sender_addr)
                    break

            # this part will be reassembling the collected chunks
            if len(chunks) == total_chunks:
                self.update_status(f"All chunks received. Assembling file...", 100)
                with open(save_path, 'wb') as f:
                    for i in range(total_chunks):
                        f.write(chunks[i])

                self.update_status(f"File successfully saved as '{filename}'!", 100)
                messagebox.showinfo("Success", f"File received and saved to:\n{save_path}")
            else:
                raise ConnectionError(f"Transfer incomplete. Received {len(chunks)}/{total_chunks} chunks.")

        except socket.timeout:
            self.update_status("Error: Timed out waiting for packet.", 0)
            messagebox.showerror("Error", "Receiver timed out. The sender may have disconnected.")
        except Exception as e:
            self.update_status(f"Error: {e}", 0)
            messagebox.showerror("Transfer Failed", f"An error occurred: {e}")
        finally:
            if self.sock:
                self.sock.close()
            self.update_ui_state(is_active=False)

    def on_closing(self):
        if self.sock:
            self.sock.close()
        self.window.destroy()


if __name__ == "__main__":
    window = tk.Tk()
    app = UDPApp(window)
    window.protocol("WM_DELETE_WINDOW", app.on_closing)
    window.mainloop()
import tkinter as tk
import socket
import os
from tkinter import filedialog , messagebox
from threading import Thread


class UDPApp:
    
    def __init__(self, window):
        self.window = window
        self.window.title("UDP FILE TRANSFER TOOL")
        self.window.geometry("500x600")
        #self.window.config("#42f5cb")
        self.setup_gui()

    
    def setup_gui(self):
        tk.Label(self.window, text="File:").grid(row=0, column=0)
        self.entry_file = tk.Entry(self.window, width=40)
        self.entry_file.grid(row=0, column=1)
        
        
        tk.Button(self.window, text="Browse", command=lambda : self.select_file(self.preview_label)).grid(row=0, column=2)
    
        tk.Label(self.window, text="Receiver IP:").grid(row=1, column=0)
        self.entry_ip = tk.Entry(self.window)
        self.entry_ip.grid(row=1, column=1)
        self.entry_ip.insert(0, "127.0.0.1")
    
        tk.Label(self.window, text="Port:").grid(row=2, column=0)
        self.entry_port = tk.Entry(self.window)
        self.entry_port.grid(row=2, column=1)
        self.entry_port.insert(0, "5000")
    
        self.status_label = tk.Label(self.window, text="Ready")
        self.status_label.grid(row=3, column=0, columnspan=3)
    
        tk.Button(self.window, text="Send File", command=self.send_file).grid(row=4, column=1)
        tk.Button(self.window, text="Receive File", command=self.receive_file).grid(row=5, column=1)
    
        self.preview_label = tk.Label(self.window)
        self.preview_label.grid(row=2, column=0)
        
    def select_file(entry_widget,preview_label):
        file_path = filedialog.askopenfilename()
        """ if file_path:
            #entry_widget.delete(0, tk.END)
            entry_widget.insert(0, file_path)"""
        
        # Show file info preview
        file_name = os.path.basename(file_path)
        file_size = round(os.path.getsize(file_path) / (1024*1024), 2)  # MB
        preview_label.config(
            text=f"Selected: {file_name}\nSize: {file_size} MB",
            fg="green"
        )

    def update_stutas():
        pass 

    def validate_ip_port(ip , port):
        pass

    def create_udp_socket():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        return sock 



    #send one file chunk 
    def send_chunk(sock, chunk, seq_num, receiver_ip, receiver_port, max_retries=3):
        packet = f"{seq_num}:".encode() + chunk  
        for _ in range(max_retries):
            try:
                sock.sendto(packet, (receiver_ip, receiver_port))
                ack, _ = sock.recvfrom(1024)  
                if ack.decode() == f"ACK:{seq_num}":
                    return True
            except socket.timeout:
                continue  
        return False  
  
  

    def receive_chunk(sock):
        """Receive a chunk and send ACK"""
        try:
            data, addr = sock.recvfrom(1024)
            seq_num, chunk = data.split(b':', 1)
            sock.sendto(f"ACK:{seq_num.decode()}".encode(), addr)
            return int(seq_num), chunk, addr
        except (socket.timeout, ValueError):
            return None

    #manages file transfer 
    def send_file(file_path , receiver_ip , port):
   
        sock = create_udp_socket()
        failed_chunks = []
    
        for seq_num, chunk in enumerate(split_file(file_path)):
            if not send_chunk(sock, chunk, seq_num, receiver_ip, port):
                failed_chunks.append(seq_num)
    
        sock.close()
        if failed_chunks:
            print(f"Failed chunks: {failed_chunks}")  
        else:
            print("File sent successfully!")





    def receive_file(self,save_path, port):
        if not save_path:
            self.update_status("Error: No save location selected")
            messagebox.showerror("Error", "Select a save location!")
            return
        if not self.validate_ip_port("0.0.0.0", port)[0]:
            self.update_status("Error: Invalid port")
            messagebox.showerror("Error", "Invalid port")
            return
        port = int(port)
        sock = self.create_udp_socket()
        sock.bind(("0.0.0.0", port))
        chunks = {}
        self.update_status(f"Listening on port {port}...")
        
        while len(chunks) < 10000:  # Arbitrary limit to prevent infinite loop
            seq_num, chunk, addr = self.receive_chunk(sock)
            if seq_num is None:
                continue
            chunks[seq_num] = chunk
            self.update_status(f"Received chunk {seq_num} from {addr[0]}")
            # Simple completion check: assume transfer stops after 5s of no packets
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


    def split_file(file_path, chunk_size=1024):
        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
            yield chunk




    def resend_packet(packet, receiver_ip, port, max_retries=3):
        pass

    def validate_ack(ack_packet, expected_seq):
        pass

    def log_error(error_msg):
        pass




    def reassemble_file(self, chunks, output_path):
        with open(output_path, 'wb') as file:
            for seq_num in sorted(chunks.keys()):
                file.write(chunks[seq_num])



    def verify_file_integrity(original_path, received_path):
        pass



    def generate_checksum(file_path):
    
        pass

    def chunk_to_packet(seq_num, chunk):
        pass

    def packet_to_chunk(packet):
        pass

    
    def on_send_click(self):
        file_path = self.entry_file.get()
        ip = self.entry_ip.get()
        port = int(self.entry_port.get())
        
        def status_update(message):
            self.status_label.config(text=message)
            self.window.update()
        
        # Run in thread to avoid GUI freeze
        Thread(target=send_file, args=(file_path, ip, port)).start()
    
    def on_receive_click(self):
        save_path = filedialog.asksaveasfilename()
        port = int(self.entry_port.get())
        
        def status_update(message):
            self.status_label.config(text=message)
            self.window.update()
        
        Thread(target=receive_file, args=(save_path, port)).start()
    def on_closing(self):
        self.window.destroy()
      
if __name__ == "__main__":
    window = tk.Tk()
    app = UDPApp(window)
    window.protocol("WM_DELETE_WINDOW", app.on_closing)
    window.mainloop()
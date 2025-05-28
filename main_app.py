import tkinter as tk
import socket 


def select_file():
    pass

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




def receive_file(save_path, port):
    pass

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




def reassemble_file(chunks, output_path):
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

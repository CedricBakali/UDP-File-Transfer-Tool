import tkinter as tk
import socket 
from tkinter import massegebox

def select_file():
    pass

def update_stutas():
    pass 

def validate_ip_port(ip , port):
    pass

def create_udp_socket():
    pass

def send_file(file_path , receiver_ip , port):
    pass

def receive_file(save_path, port):
    pass

def split_file(file_path, chunk_size):
    pass

def resend_packet(packet, receiver_ip, port, max_retries=3):
    pass

def validate_ack(ack_packet, expected_seq):
    pass

def log_error(error_msg):
    pass

def reassemble_file(chunks, output_path):
    pass

def verify_file_integrity(original_path, received_path):
    pass



def generate_checksum(file_path):
    
    pass

def chunk_to_packet(seq_num, chunk):
    pass

def packet_to_chunk(packet):
    pass

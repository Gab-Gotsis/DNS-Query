#python3 client.py resolver_ip resolver_port name
import socket
import sys
import random
import numpy

if len(sys.argv) < 5:
    print("Error: invalid arguments")
    print("Usage: python3 resolver.py resolver_port timeout")
    sys.exit()

resolver_ip = str(sys.argv[1])
resolver_port = int(sys.argv[2])
name = str(sys.argv[3])
timeout = sys.argv[4]

#header
header = bytearray([0] * 12)
query_id = random.randint(60000, 65530)

qr = 0
opcode = 0
aa = 0
tc = 0
rd = 0
ra = 0
z = 0
rcode = 0
qdcount = 1
ancount = 0
nscount = 0
arcount = 0

header[0] = query_id // 256
header[1] = query_id % 256
header[2] = qr << 7 | opcode << 3 | aa << 2 | tc << 1 | rd
header[3] = ra << 7 | z << 4 | rcode
header[4] = qdcount // 256
header[5] = qdcount % 256
header[6] = ancount // 256
header[7] = ancount % 256
header[8] = nscount // 256
header[9] = nscount % 256
header[10] = arcount // 256
header[11] = arcount % 256

#print(header)

#question
#generates qname
labels = name.split(".")
label_len = [0] * len(labels)
count = 0
for label in labels:
    label_len[count] = len(label.encode('utf-8')).to_bytes(1, byteorder='big')
    count = count + 1

count = 0
qname = b''
for label in labels:
    qname = qname + label_len[count] + label.encode('utf-8')
    count = count + 1

qname = qname + b'\x00'

qtype = b'\x00\x01'
qclass = b'\x00\x01'
question = b''
question = qname + qtype + qclass


answer_authority_additional = bytearray([0] * 6)

to_send = header + question 


clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

clientSocket.settimeout(int(timeout))
try: 
    clientSocket.sendto(to_send, (resolver_ip, resolver_port))
    modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
except socket.timeout:
    print("Error: Request timed out")

if modifiedMessage == b'servertimedout':
    print("Error: Request timed out")
    sys.exit()


r_id = modifiedMessage[0:2]
r_qr = modifiedMessage[2] >> 7
r_opcode = (modifiedMessage[2] >> 3) & 0b00001111
r_aa = (modifiedMessage[2] >> 2) & 0b00000001
r_tc = (modifiedMessage[2] >> 1) & 0b00000001
r_rd = modifiedMessage[2] & 0b00000001
r_ra = modifiedMessage[3] >> 7
r_z = (modifiedMessage[3] >> 4) & 0b00000111
r_rcode = modifiedMessage[3] & 0b00001111
r_qdcount = modifiedMessage[4] * 256 + modifiedMessage[5]
r_ancount = modifiedMessage[6] * 256 + modifiedMessage[7]
r_nscount = modifiedMessage[8] * 256 + modifiedMessage[9]
r_arcount = modifiedMessage[10] * 256 + modifiedMessage[11]

if r_rcode == 1:
    print("Error: Format error - Server was unable to interpret the query.")
    sys.exit()
elif r_rcode == 2:
    print("Error: Server failure - Unable to process as there was an issue with the name server.")
    sys.exit()
elif r_rcode == 3:
    print("Error: Name error - Domain name referenced in the query does not exist.")
    sys.exit()
elif r_rcode == 4:
    print("Error: Not implemented - Server does not support the requested query.")
    sys.exit()
elif r_rcode == 5:
    print("Error: Refused - Server refused to process the query for privacy reasons.")
    sys.exit()



question_start = 12
question_segment = 1
btye_count = 0
while question_segment != 0:
    question_segment = int.from_bytes(modifiedMessage[question_start:question_start+1], "big")
    if (question_segment == 0):
        break
    btye_count = btye_count + question_segment + 1
    question_start = question_start + question_segment + 1

answer_start = 12+5+btye_count


print("ANSWERS:")
for j in range(0, r_ancount):
    segment_count = 1
    name = ""
    while segment_count != 0:
            segment_count = int.from_bytes(modifiedMessage[answer_start:answer_start+1], "big")
            if name == "":
                name = name + modifiedMessage[answer_start+1:answer_start+segment_count+1].decode('utf-8') 
            else:
                name = name + "." + modifiedMessage[answer_start+1:answer_start+segment_count+1].decode('utf-8') 
            answer_start = answer_start + segment_count + 1
    a_type = "Not A"
    a_class = "Not In"     
    if modifiedMessage[answer_start:answer_start+2] == b'\x00\x01':
        a_type = "A"
    if modifiedMessage[answer_start+2:answer_start+4] == b'\x00\x01':
        a_class = "IN"

    answer_start = answer_start + 8 
    a_data_len = int.from_bytes(modifiedMessage[answer_start:answer_start+2], "big")
    answer_start = answer_start + 2
    ip_answer = ""
    for i in range(0, a_data_len):
        
        if i == 0:
            ip_answer = ip_answer + str(int.from_bytes(modifiedMessage[answer_start:answer_start+1], "big"))
        else:
            ip_answer = ip_answer + "." + str(int.from_bytes(modifiedMessage[answer_start:answer_start+1], "big"))

        answer_start = answer_start + 1

    
    print(name + " " + a_class + " " + a_type + " " + " " + ip_answer)
clientSocket.close()
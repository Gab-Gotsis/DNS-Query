#1. recieve client commands.
#2. construct a DNS query for the given name (refer to spec for hints), send to root
#3. recieve response from root, repeat sending until name found.
#4. return response to client
import socket
import sys
import random
import numpy as np

EXTERNAL_SERVER_PORT = 53

if len(sys.argv) < 3:
    print("Error: invalid arguments")
    print("Usage: python3 resolver.py resolver_port timeout")
    sys.exit()

serverPort = int(sys.argv[1])
timeout = int(sys.argv[2])


#for communication with client
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSocket.bind(('localhost', serverPort))


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



def get_ns_ip(a_record, ns_ip, start_point):

    externalSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    externalSocket.sendto(a_record, (ns_ip, EXTERNAL_SERVER_PORT))

    response, ext_address = externalSocket.recvfrom(2048)

    start_point = start_point + 12 + 5 #12 for header, 5 for question
    start_point = get_name(start_point, response)[1]
    start_point = start_point + 2 + 2 + 4 #2 for type, 2 for class, 4 for ttl, 2 for rdlength
    rdlength = response[start_point:start_point+2]
    start_point = start_point + 2
    answer_ip = []
    for i in range(0, int.from_bytes(rdlength, "big")):
        answer_ip.insert(i, response[start_point+i:start_point+i+1])
    start_point = start_point + int.from_bytes(rdlength, "big")

    answer_ip = '.'.join(str(int.from_bytes(i, "big")) for i in answer_ip)
    return answer_ip


def get_name(start_point, data):
    function_count = 0
    names = []
    segment_count = int.from_bytes(data[start_point:start_point+1], "big")

    if (segment_count >= 192):
        pointer = int.from_bytes(data[start_point:start_point+2], "big") - 49152
        names.insert(function_count, get_name(pointer, response)[0])
        return names, start_point + 2

    while segment_count != 0:
        names.insert(function_count, data[start_point+1:start_point+segment_count+1])
        function_count = function_count + 1
        start_point = start_point + segment_count + 1
        segment_count = int.from_bytes(data[start_point:start_point+1], "big")
        
        if (segment_count >= 192):
            #get the pointer minus first 2 bits
            pointer = int.from_bytes(data[start_point:start_point+2], "big") - 49152
            names.insert(function_count, get_name(pointer, response)[0])
            return names, start_point + 2
    return names, start_point + 1
def flatten_list(l):
    flat_list = []
    for el in l:
        if not isinstance(el, bytes) and isinstance(el, list):
            flat_list.extend(flatten_list(el))
        else:
            flat_list.append(el)
    return flat_list 

def get_qbyte_count(data):
    question_start = 12
    question_segment = 1
    btye_count = 0
    while question_segment != 0:
        question_segment = int.from_bytes(data[question_start:question_start+1], "big")
        if (question_segment == 0):
            break
        btye_count = btye_count + question_segment + 1
        question_start = question_start + question_segment + 1
    return btye_count

def create_query(ser_name, f_query_id):
    #header
    f_header = bytearray([0] * 12)

    f_qr = 0
    f_opcode = 0
    f_aa = 0
    f_tc = 0 
    f_rd = 0
    f_ra = 0 
    f_z = 0
    f_rcode = 0
    f_qdcount = 1
    f_ancount = 0
    f_nscount = 0
    f_arcount = 0

    f_header[0] = f_query_id // 256
    f_header[1] = f_query_id % 256
    f_header[2] = f_qr << 7 | f_opcode << 3 | f_aa << 2 | f_tc << 1 | f_rd
    f_header[3] = f_ra << 7 | f_z << 4 | f_rcode
    f_header[4] = f_qdcount // 256
    f_header[5] = f_qdcount % 256
    f_header[6] = f_ancount // 256
    f_header[7] = f_ancount % 256
    f_header[8] = f_nscount // 256
    f_header[9] = f_nscount % 256
    f_header[10] = f_arcount // 256
    f_header[11] = f_arcount % 256
    f_label_len = [0] * len(ser_name)
    f_count = 0
    f_q_btye_count = 0
    for label in ser_name:
        f_label_len[f_count] = len(label).to_bytes(1, byteorder='big')
        f_count = f_count + 1
        f_q_btye_count = f_q_btye_count + len(label) + 1

    f_count = 0
    f_qname = b''
    for label in ser_name:
        f_qname = f_qname + f_label_len[f_count] + label  
        f_count = f_count + 1
    f_qname = f_qname + b'\x00'
    f_qtype = b'\x00\x01'
    f_qclass = b'\x00\x01'
    f_question = b''
    f_question = f_qname + f_qtype + f_qclass
    #question
    return f_header + f_question, f_q_btye_count
def make_response(records_with_ip):
    f_header = bytearray([0] * 12)

    f_qr = 1
    f_opcode = 0
    f_aa = 1
    f_tc = 0 
    f_rd = 0
    f_ra = 0 
    f_z = 0
    f_rcode = 0
    f_qdcount = 1
    f_ancount = len(records_with_ip)
    f_nscount = 0
    f_arcount = 0

    f_header[0] = int.from_bytes(id, "big") // 256
    f_header[1] = int.from_bytes(id, "big") % 256
    f_header[2] = f_qr << 7 | f_opcode << 3 | f_aa << 2 | f_tc << 1 | f_rd
    f_header[3] = f_ra << 7 | f_z << 4 | f_rcode
    f_header[4] = f_qdcount // 256
    f_header[5] = f_qdcount % 256
    f_header[6] = f_ancount // 256
    f_header[7] = f_ancount % 256
    f_header[8] = f_nscount // 256
    f_header[9] = f_nscount % 256
    f_header[10] = f_arcount // 256
    f_header[11] = f_arcount % 256
    # f_label_len = [0] * len(ser_name)
    # f_count = 0
    # f_q_btye_count = 0
    rname = b''
    ranswer = b''
    for record in records_with_ip:
        rname = b''
        for label in flatten_list(record[0]):
            rname = rname + len(label).to_bytes(1, byteorder='big') + label
        rname = rname + b'\x00'
        rtype = record[1]
        rclass = record[2]
        ttl = record[3]
        rdlength = record[4]
        rdata = b''
        record[5] = record[5].split(".")
        for label in record[5]:
            rdata = rdata + int(label).to_bytes(1, byteorder='big')
        ranswer = ranswer + rname + rtype + rclass + ttl + rdlength + rdata
    return f_header + message[12:] + ranswer

while 1:
    message, clientAddress = serverSocket.recvfrom(2048)

    id = message[0:2]
    qr_opcode_aa_tc_rd = message[2:3]
    ra_z_rcode = message[3:4]
    qdcount = message[4:6]
    ancount = message[6:8]
    nscount = message[8:10]
    arcount = message[10:12]
    question = message[12:]

    segment_count = 1
    q_btye_count = 0
    q_count = 0
    labels = []

    #if client has error message
    rcode = int.from_bytes(ra_z_rcode, "big") & 0b00001111
    if (rcode == 1 or rcode == 2 or rcode == 3 or rcode == 4 or rcode == 5):
        serverSocket.sendto(message, clientAddress)
        #no other servers to check, this is from client
        sys.exit()

    while segment_count != 0:
        segment_count = int.from_bytes(question[q_btye_count:q_btye_count+1], "big")
        if (segment_count == 0):
            break
        labels.insert(q_count, question[q_btye_count+1:q_btye_count+segment_count+1])
        q_btye_count = q_btye_count + segment_count + 1
        q_count = q_count + 1

    qtype = question[q_btye_count+1:q_btye_count+3]
    qclass = question[q_btye_count+3:q_btye_count+5]

    f = open('named.root', 'r')    
    line = ""
    while True:
        line = f.readline()
        if not line:
            break
        
        if line[0] == ';' or line[0] == '.' or line == "" or ' AAAA ' in line:
            continue
        break
    root_address = line.split(" ")
    root_address = root_address[-1].strip()
    cur_address = root_address
    f.close()

    server_we_tried = 0
    server_we_timeout = 0

    while 1:
        externalSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        externalSocket.sendto(message, (cur_address, EXTERNAL_SERVER_PORT))
        externalSocket.settimeout(timeout)

        try: 
            response, ext_address = externalSocket.recvfrom(2048)
        except socket.timeout:
            server_we_timeout = server_we_timeout + 1
            if len(ips_from_responses) == 0:
                if (server_we_timeout == len(root_address)):
                    serverSocket.sendto(b'servertimedout', clientAddress)
                    sys.exit()
                cur_address = root_address[server_we_timeout]

            else:
                if (server_we_timeout == len(ips_from_responses)):
                    serverSocket.sendto(b'servertimedout', clientAddress)
                    sys.exit()
                cur_address = ips_from_responses[server_we_timeout]
            continue

        server_we_timeout = 0

        id = response[0:2]
        qr_opcode_aa_tc_rd = response[2:3]
        ra_z_rcode = response[3:4]
        qdcount = response[4:6]
        ancount = response[6:8]
        nscount = response[8:10]
        arcount = response[10:12]
        
        q_btye_count = get_qbyte_count(response)

        check_rcode = int.from_bytes(ra_z_rcode, "big") & 0b00001111
        if (check_rcode == 1 or check_rcode == 3 or check_rcode == 4 or check_rcode == 5):
            serverSocket.sendto(message, clientAddress)
            #no other servers to check, this is from client
            sys.exit()

        
        if (check_rcode == 2):
            server_we_tried = server_we_tried + 1
            if len(ips_from_responses) == 0:
                if (server_we_tried == len(root_address)):
                    serverSocket.sendto(message, clientAddress)
                    sys.exit()
                cur_address = root_address[server_we_tried]
            else:
                if (server_we_tried == len(ips_from_responses)):
                    serverSocket.sendto(message, clientAddress)
                    sys.exit()
                cur_address = ips_from_responses[server_we_tried]
            continue
        server_we_tried = 0


        count = q_btye_count + 5 + 12 #5 for 2 octels after the question, 12 for the header, aligns it to start of answer


        answers = []
        authority = []
        additional = []

        record = []

        for i in range(0, int.from_bytes(ancount, "big")):
            record = []
            record.insert(0, get_name(count, response)[0])
            count = get_name(count, response)[1]
            record.insert(1, response[count:count+2])
            count = count + 2
            record.insert(2, response[count:count+2])
            count = count + 2
            record.insert(3, response[count:count+4])
            count = count + 4
            record.insert(4, response[count:count+2])
            count = count + 2
            #if type is A, then ip
            if (record[1] == b'\x00\x01'):
                answer_ip = []
                for i in range(0, int.from_bytes(record[4], "big")):
                    answer_ip.insert(i, response[count+i:count+i+1])
                count = count + int.from_bytes(record[4], "big")

                answer_ip = '.'.join(str(int.from_bytes(i, "big")) for i in answer_ip)

                record.insert(5, answer_ip)
            elif (record[1] == b'\x00\x02' or record[1] == b'\x00\x05'):
                record.insert(5, get_name(count, response)[0])
                count = count + int.from_bytes(record[4], "big")
            else:
                record.insert(5, response[count:count+int.from_bytes(record[4], "big")])
                count = count + int.from_bytes(record[4], "big")
            answers.insert(i, record)

        for i in range(0, int.from_bytes(nscount, "big")):
            record = []
            record.insert(0, get_name(count, response)[0])
            count = get_name(count, response)[1]
            record.insert(1, response[count:count+2])
            count = count + 2
            record.insert(2, response[count:count+2])
            count = count + 2
            record.insert(3, response[count:count+4])
            count = count + 4
            record.insert(4, response[count:count+2])
            count = count + 2
            #if type is A, then ip
            if (record[1] == b'\x00\x01'):
                answer_ip = []
                for i in range(0, int.from_bytes(record[4], "big")):
                    answer_ip.insert(i, response[count+i:count+i+1])
                count = count + int.from_bytes(record[4], "big")

                answer_ip = '.'.join(str(int.from_bytes(i, "big")) for i in answer_ip)

                record.insert(5, answer_ip)
            elif (record[1] == b'\x00\x02'):
                record.insert(5, get_name(count, response)[0])
                count = count + int.from_bytes(record[4], "big")
            else:
                record.insert(5, response[count:count+int.from_bytes(record[4], "big")])
                count = count + int.from_bytes(record[4], "big")
            authority.insert(i, record)
        
        for i in range(0, int.from_bytes(arcount, "big")):
            record = []
            record.insert(0, get_name(count, response)[0])
            count = get_name(count, response)[1]
            record.insert(1, response[count:count+2])
            count = count + 2
            record.insert(2, response[count:count+2])
            count = count + 2
            record.insert(3, response[count:count+4])
            count = count + 4
            record.insert(4, response[count:count+2])
            count = count + 2
            #if type is A, then ip

            if (record[1] == b'\x00\x01'):
                answer_ip = []
                for i in range(0, int.from_bytes(record[4], "big")):
                    answer_ip.insert(i, response[count+i:count+i+1])
                count = count + int.from_bytes(record[4], "big")

                answer_ip = '.'.join(str(int.from_bytes(i, "big")) for i in answer_ip)

                record.insert(5, answer_ip)
            elif (record[1] == b'\x00\x02'):
                record.insert(5, get_name(count, response)[0])
                count = count + int.from_bytes(record[4], "big")
            else:
                record.insert(5, response[count:count+int.from_bytes(record[4], "big")])
                count = count + int.from_bytes(record[4], "big")

            additional.insert(i, record)
        
        ips_from_responses = []
        ips_from_rep_count = 0
        if int.from_bytes(ancount, "big") == 0:
            #then we go through authority and additional to find the next server to query
            for record in authority:
                if (record[1] == b'\x00\x01'):
                    ips_from_responses.insert(ips_from_rep_count, record[5])
                    ips_from_rep_count = ips_from_rep_count + 1
            
            for record in additional:
                if (record[1] == b'\x00\x01'):
                    ips_from_responses.insert(ips_from_rep_count, record[5])
                    ips_from_rep_count = ips_from_rep_count + 1
        else: 
            
            records_with_ip = []
            for record in answers:
                if (record[1] == b'\x00\x01'):
                    records_with_ip.insert(ips_from_rep_count, record)
                    ips_from_responses.insert(ips_from_rep_count, record[5])
                    ips_from_rep_count = ips_from_rep_count + 1
            #send special message to client.
            
            #if its empty, its cname time
            if (ips_from_responses != []):
                u_response = make_response(records_with_ip)
                serverSocket.sendto(u_response, clientAddress)
                break

        
        if (ips_from_responses == []):
            #look for cname
            #id changes, must fix
            cnames_index = 0
            cnames = []
            for record in answers:
                if (record[1] == b'\x00\x05'):
                    cnames.insert(cnames_index, record[5])
                    cnames_index = cnames_index + 1 

            if (cnames != []):
                cname_value = create_query(flatten_list(cnames[0]), int.from_bytes(id, "big"))[0]
                message = cname_value
                cur_address = root_address
                continue
            
            ns_index = 0
            ns_responses = []
            for record in authority:
                if (record[1] == b'\x00\x02'):
                    ns_responses.insert(ns_index, record[5])
                    ns_index = ns_index + 1

            if (ns_responses != []):

                
                ns_response = ""
                for label in flatten_list(ns_responses[0]):
                    ns_response = ns_response + label.decode('utf-8') + "."

                ns_id = random.randint(60000, 65530)
                ns_query = create_query(flatten_list(ns_responses[0]), ns_id)[0]

                ns_ip = get_ns_ip(ns_query, ns_response, create_query(flatten_list(ns_responses[0]), ns_id)[1])
                ips_from_responses.insert(0, ns_ip)
                #process response for first ip in answer section
            else:
                print("no clue whats going on here")
                sys.exit()

        cur_address = ips_from_responses[0]
    
    


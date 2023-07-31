import socket
import pickle
from encrypts import Blowfish2,RSA
import time
import hashlib
import tracemalloc
import psutil,sys
# Create a socket object
clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Get local machine name
host = socket.gethostname()

port = 9999

clientsocket.connect((host, port))

total_t=0
while True:
    obj1 = RSA.RSA()
    blow1 = Blowfish2.Blowfish()
    process = psutil.Process()
    start_cpu_key= process.cpu_percent()
    tracemalloc.start()
    current_key1, peak_key1 = tracemalloc.get_traced_memory()
    # msg = clientsocket.recv(1024)
    start_time_key= time.perf_counter()
    pub,prv=obj1.generate_keypair()
    n,e=pub
    data = pickle.dumps(pub)
    clientsocket.sendall(data)
    msg=clientsocket.recv(1024*100)
    seckey=pickle.loads(msg)
    z=obj1.decrypt(seckey,prv)
    # print("size of key ",z)
    hex_num = hex(z)[2:]
    # print("hexa number is",len(hex_num))
    # hex_num_stripped = hex_num.strip()
    # try:
    #  byte_object = bytes.fromhex(hex_num_stripped)
    # # Continue with further processing of the byte object
    # except ValueError:
    # # Handle the error when a non-hexadecimal character is found
    #  print("Invalid hexadecimal string. Please provide a valid input.",hex_num)
    # byte_object = bytes.fromhex(hex_num)
    byte_object = z.to_bytes((z.bit_length() + 7) // 8, 'big')
    # print(byte_object)
    # print(byte_object)
    blow1.keygeneration(byte_object)
    end_time_key= time.perf_counter()
    current_key2, peak_key2 = tracemalloc.get_traced_memory()
    end_cpu_key= process.cpu_percent()
    time_taken=end_time_key-start_time_key
    cpu_usage=end_cpu_key-end_cpu_key
    mem_usage=current_key2-current_key1
    # samplelist=[cpu_usage,time_taken,mem_usage]
    # data = pickle.dumps(samplelist)
    # clientsocket.sendall(data)

    msg=clientsocket.recv(1024*100)
    data=pickle.loads(msg)
    msg2=clientsocket.recv(1024)
    data2=pickle.loads(msg2)
    start_time1 = time.perf_counter()
    endata=blow1.blowfishdecrypt(data)
    data2=blow1.blowfishdecrypt(data2)
    end_time1 = time.perf_counter()
    total_time=end_time1-start_time1
    start_cpu1 = process.cpu_percent()
    current, peak = tracemalloc.get_traced_memory()
    hashed_word = hashlib.sha256(blow1.num2text(endata).encode()).hexdigest()

    if hashed_word==blow1.num2text(data2):
        print("hash values match")
    else:
        print("error occured")
    total_t = total_time + time_taken
    samplelist=[start_cpu1-start_cpu_key,total_t,current-current_key1]
    data = pickle.dumps(samplelist)
    clientsocket.sendall(data)
clientsocket.close()
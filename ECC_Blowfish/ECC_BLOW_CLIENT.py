import socket
import pickle
import time
import tracemalloc
import psutil,sys
from tinyec import registry
from encrypts import Blowfish2
import hashlib, secrets, binascii
import numpy as np
# Create a socket object
def ecc_point_to_128_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    key_256_bit = sha.digest()
    key_128_bit = key_256_bit[:16]  # Extract the first 16 bytes (128 bits) of the 256-bit key
    return key_128_bit

clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Get local machine name
host = socket.gethostname()

port = 9999

clientsocket.connect((host, port))
blow2=Blowfish2.Blowfish()
total_t=0
while True:
    process = psutil.Process()
    start_cpu_key= process.cpu_percent()
    tracemalloc.start()
    current_key1, peak_key1 = tracemalloc.get_traced_memory()
    # msg = clientsocket.recv(1024)
    start_time_key= time.perf_counter()
    curve = registry.get_curve('secp256r1')
    privKey = secrets.randbelow(curve.field.n)
    pubKey = privKey * curve.g
    data = pickle.dumps(pubKey)
    clientsocket.sendall(data)
    msg=clientsocket.recv(1024)
    serverpub=pickle.loads(msg)
    sharedkey=privKey*serverpub
    secretKey = ecc_point_to_128_bit_key(sharedkey)
    blow2.keygeneration(secretKey)
    end_time_key= time.perf_counter()
    current_key2, peak_key2 = tracemalloc.get_traced_memory()
    end_cpu_key= process.cpu_percent()
    time_taken=end_time_key-start_time_key
    print("time taken for key", time_taken-5)
    cpu_usage=end_cpu_key-end_cpu_key
    mem_usage=current_key2-current_key1
    # samplelist=[cpu_usage,time_taken,mem_usage]
    # data = pickle.dumps(samplelist)
    # clientsocket.sendall(data)
    msg=clientsocket.recv(1024*100)
    data=pickle.loads(msg)
    msg2=clientsocket.recv(1024)
    data2 = pickle.loads(msg2)
    start_time1 = time.perf_counter()
    y = blow2.blowfishdecrypt(data)
    data2=blow2.blowfishdecrypt(data2)
    end_time1 = time.perf_counter()
    # hashed_word = hashlib.sha256(aes2.num2text(y).encode()).hexdigest()

    start_cpu1 = process.cpu_percent()
    current, peak = tracemalloc.get_traced_memory()
    # hash_object = hashlib.sha256(y.encode())
    hashed_word = hashlib.sha256(blow2.num2text(y).encode()).hexdigest()
    if hashed_word==blow2.num2text(data2):
        print("hash values match")
    else:
        print("error occured")
        clientsocket.close()
    print("time taken for encrpt", end_time1-start_time1)
    total_t = (end_time1 - start_time1) + time_taken + total_t
    samplelist=[start_cpu1-start_cpu_key,total_t,current-current_key1]
    total_t = -5
    data = pickle.dumps(samplelist)
    clientsocket.sendall(data)
clientsocket.close()
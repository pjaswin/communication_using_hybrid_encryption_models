import socket
import pickle
import time
import tracemalloc
import psutil,sys
from tinyec import registry
from encrypts import AES
import hashlib, secrets, binascii
import numpy as np
# Create a socket object
# def ecc_point_to_256_bit_key(point):
#     sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
#     sha.update(int.to_bytes(point.y, 32, 'big'))
#     return sha.digest()
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
total_t=0
while True:
    process = psutil.Process()
    start_cpu_key= process.cpu_percent()
    tracemalloc.start()
    current_key1, peak_key1 = tracemalloc.get_traced_memory()
    # msg = clientsocket.recv(1024)
    start_time= time.perf_counter()
    curve = registry.get_curve('secp256r1')
    privKey = secrets.randbelow(curve.field.n)
    pubKey = privKey * curve.g
    data = pickle.dumps(pubKey)
    clientsocket.sendall(data)
    msg=clientsocket.recv(1024)
    serverpub=pickle.loads(msg)
    sharedkey=privKey*serverpub
    secretKey = ecc_point_to_128_bit_key(sharedkey)
    aes2=AES.AES(secretKey)
    end_time= time.perf_counter()
    time_taken1=end_time-start_time
    print("time taken for key", (time_taken1-5))

    # samplelist=[cpu_usage,time_taken,mem_usage]
    # data = pickle.dumps(samplelist)
    # clientsocket.sendall(data)
    """*********************************************************"""
    msg=clientsocket.recv(1024*100)
    msg2=clientsocket.recv(1024)
    data = pickle.loads(msg)
    data2 = pickle.loads(msg2)
    start_time = time.perf_counter()
    y = aes2.Decrypt(data)
    data2=aes2.Decrypt(data2)
    # hashed_word = hashlib.sha256(aes2.num2text(y).encode()).hexdigest()
    end_time = time.perf_counter()
    start_cpu1 = process.cpu_percent()
    current, peak = tracemalloc.get_traced_memory()
    hash_object = hashlib.sha256(y.encode())
    hashed_word = hash_object.hexdigest()
    if hashed_word==data2:
        print("hash values match")
    else:
        print("error occured")
        clientsocket.close()
    print("time taken for encryption", end_time-start_time)
    total_t=(end_time-start_time)+time_taken1 + total_t
    print(total_t)
    samplelist=[start_cpu1-start_cpu_key,total_t,current-current_key1]
    total_t=-5
    data = pickle.dumps(samplelist)
    clientsocket.sendall(data)
clientsocket.close()
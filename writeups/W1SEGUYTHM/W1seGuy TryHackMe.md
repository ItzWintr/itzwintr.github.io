First of all, we have to download and understand what is this room about, because this is not a "hacking" challenge exactly.

We will start checking the source code that we can download directly from the room itself:
```
import random
import socketserver 
import socket, os
import string

flag = open('flag.txt','r').read().strip()

def send_message(server, message):
    enc = message.encode()
    server.send(enc)

def setup(server, key):
    flag = 'THM{thisisafakeflag}' 
    xored = ""

    for i in range(0,len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))

    hex_encoded = xored.encode().hex()
    return hex_encoded

def start(server):
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
    key = str(res)
    hex_encoded = setup(server, key)
    send_message(server, "This XOR encoded text has flag 1: " + hex_encoded + "\n")
    
    send_message(server,"What is the encryption key? ")
    key_answer = server.recv(4096).decode().strip()

    try:
        if key_answer == key:
            send_message(server, "Congrats! That is the correct key! Here is flag 2: " + flag + "\n")
            server.close()
        else:
            send_message(server, 'Close but no cigar' + "\n")
            server.close()
    except:
        send_message(server, "Something went wrong. Please try again. :)\n")
        server.close()

class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        start(self.request)

if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)
    server.serve_forever()
```

This is a classic cryptography challenge designed to teach you how to perform a Known-Plaintext Attack by exploiting a vulnerable implementation of XOR. Instead of trying to break complex mathematical algorithms, the exercise demonstrates how a logical flaw in the system’s architecture completely undermines its security: the server makes the fatal mistake of giving you the encrypted result of a text string that you already know in advance` (THM{thisisafakeflag})`. Since the XOR operation is perfectly symmetric, the key cybersecurity lesson here is that exposing or making the structure of your data (the “plaintext”) predictable gives the attacker the exact piece they need to reverse the equation, reveal the original encryption key, and compromise the entire defense mechanism.

### Enumeration
Here there's not much enumeration to do, but with a simple nmap we can see a strange port:

```
❯ nmap -sV -O -Pn -p- --min-rate 5000 10.128.137.21
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-16 22:29 CEST
Nmap scan report for 10.128.137.21
Host is up (0.028s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
1337/tcp open  waste?
1 service unrecognized despite returning data. If you know the service/version
```

Let's perform a `nc` to see what that port hides.

```
❯ nc 10.128.137.21 1337
This XOR encoded text has flag 1: 1d251c3d42780c3d28460c152507463d59322d5108032375532521282e673b192876473b151e344f
What is the encryption key? 
```

### Breaking down the code

We know from the server code that the key is exactly 5 characters long. Therefore, we don't need to decrypt the entire message at once; decrypting the first 5-byte block is enough to obtain the full key.

- `1d251c3d42` These are the first 5 bytes. Remember that in hexadecimal, every 2 characters represent 1 byte.
- `THM{t` These are the first 5 characters of the fake flag that the server encrypted:  `THM{thisisafakeflag}`.

In order for the computer to perform the XOR (^) mathematical operation, we cannot work directly with letters or hexadecimal strings. Everything must be converted to its numerical value (bytes or integers).

### The PoC python code
So, we made a python script to automate the whole process:
```
import socket
import string

def xor_decrypt(hex_encoded, key):
    ciphertext = bytes.fromhex(hex_encoded)
    result = ""
    for i in range(len(ciphertext)):
        result += chr(ciphertext[i] ^ ord(key[i % len(key)]))
    return result

def recover_key(hex_encoded):
    ciphertext = bytes.fromhex(hex_encoded)
    known_prefix = "THM{"
    
    partial_key = ""
    for i in range(4):
        partial_key += chr(ciphertext[i] ^ ord(known_prefix[i]))
    
    charset = string.ascii_letters + string.digits
    for c in charset:
        candidate_key = partial_key + c
        decrypted = xor_decrypt(hex_encoded, candidate_key)
        if decrypted.startswith("THM{") and decrypted.endswith("}"):
            return candidate_key
    
    return None

HOST = "10.128.137.21"
PORT = 1337

s = socket.socket()
s.connect((HOST, PORT))

data = s.recv(4096).decode()
print(data)

hex_encoded = data.split(": ")[1].strip()

key = recover_key(hex_encoded)
print(f"[+] Key found: {key}")
print(f"[+] Flag 1: {xor_decrypt(hex_encoded, key)}")

question = s.recv(4096).decode()
print(question)

s.send((key + "\n").encode())

response = s.recv(4096).decode()
print(response)

s.close()
```

Now we just execute it and we should get the flags!
```
❯ python3 decode.py
This XOR encoded text has flag 1: 103f1c4c2175163d5925010f2576253043325c320519230430283b285f043603280724360f1e452c

[+] Key found: DwQ7Q
[+] Flag 1: THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
What is the encryption key? 
Congrats! That is the correct key! Here is flag 2: THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

Alright! We have the two flags, so we completed the room!
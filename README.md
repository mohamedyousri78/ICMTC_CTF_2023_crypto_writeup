# ICMTC_CTF_2023_crypto_writeup

## Easy Encryption


You were given this snippet of code as the implementation of the cryptosystem and you need to retrive the flag. 
```
from gmpy2 import next_prime
from Crypto.Util.number import getPrime,bytes_to_long
from random import randint
import os
from flask import Flask



app = Flask(__name__)
@app.route('/start/')
def decrypt():
    flag = os.environ.get("CTF_FLAG", "EGCTF{FAKE_FLAAAAAAAAAAAAG}")
    m1 = bytes_to_long(flag[:len(flag)//2])
    m2 = bytes_to_long(flag[len(flag)//2:])
    e = 0x10001
    z = getPrime(512)
    p1 = getPrime(512)
    q1 = next_prime(p1)
    n1 = p1*q1
    p2 = next_prime(q1)
    q2 = next_prime(p2)
    n2 = p2*q2
    n3 = n1 * n2
    n4 = q1 * getPrime(1024)
    c1 = (z * pow(m1,e,n3)) % n3 
    c2 = (m1*randint(1000,30000) * pow(m2,e,n4)) % n4
    
    return {'n1':int(n3) , 'n2':int(n4), 'c1':int(c1), 'c2':int(c2), 'z':int(z), 'e':int(e)}



@app.route('/')
def home():
	return "Hi!"

if __name__ == "__main__":
    app.run()



```
## Simple Cipher


## Sign Gate
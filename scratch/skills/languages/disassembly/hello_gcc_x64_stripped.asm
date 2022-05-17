
hello_gcc_x64_stripped:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <.init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 d9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd9]        # 3fe8 <puts@plt+0x2f98>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <__cxa_finalize@plt-0x2a>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 9a 2f 00 00    	push   QWORD PTR [rip+0x2f9a]        # 3fc0 <puts@plt+0x2f70>
    1026:	f2 ff 25 9b 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f9b]        # 3fc8 <puts@plt+0x2f78>
    102d:	0f 1f 00             	nop    DWORD PTR [rax]
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <__cxa_finalize@plt-0x20>
    103f:	90                   	nop

Disassembly of section .plt.got:

0000000000001040 <__cxa_finalize@plt>:
    1040:	f3 0f 1e fa          	endbr64 
    1044:	f2 ff 25 ad 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fad]        # 3ff8 <puts@plt+0x2fa8>
    104b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .plt.sec:

0000000000001050 <puts@plt>:
    1050:	f3 0f 1e fa          	endbr64 
    1054:	f2 ff 25 75 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f75]        # 3fd0 <puts@plt+0x2f80>
    105b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000001060 <.text>:
    1060:	f3 0f 1e fa          	endbr64 
    1064:	31 ed                	xor    ebp,ebp
    1066:	49 89 d1             	mov    r9,rdx
    1069:	5e                   	pop    rsi
    106a:	48 89 e2             	mov    rdx,rsp
    106d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    1071:	50                   	push   rax
    1072:	54                   	push   rsp
    1073:	4c 8d 05 66 01 00 00 	lea    r8,[rip+0x166]        # 11e0 <puts@plt+0x190>
    107a:	48 8d 0d ef 00 00 00 	lea    rcx,[rip+0xef]        # 1170 <puts@plt+0x120>
    1081:	48 8d 3d c1 00 00 00 	lea    rdi,[rip+0xc1]        # 1149 <puts@plt+0xf9>
    1088:	ff 15 52 2f 00 00    	call   QWORD PTR [rip+0x2f52]        # 3fe0 <puts@plt+0x2f90>
    108e:	f4                   	hlt    
    108f:	90                   	nop
    1090:	48 8d 3d 79 2f 00 00 	lea    rdi,[rip+0x2f79]        # 4010 <puts@plt+0x2fc0>
    1097:	48 8d 05 72 2f 00 00 	lea    rax,[rip+0x2f72]        # 4010 <puts@plt+0x2fc0>
    109e:	48 39 f8             	cmp    rax,rdi
    10a1:	74 15                	je     10b8 <puts@plt+0x68>
    10a3:	48 8b 05 2e 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f2e]        # 3fd8 <puts@plt+0x2f88>
    10aa:	48 85 c0             	test   rax,rax
    10ad:	74 09                	je     10b8 <puts@plt+0x68>
    10af:	ff e0                	jmp    rax
    10b1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    10b8:	c3                   	ret    
    10b9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    10c0:	48 8d 3d 49 2f 00 00 	lea    rdi,[rip+0x2f49]        # 4010 <puts@plt+0x2fc0>
    10c7:	48 8d 35 42 2f 00 00 	lea    rsi,[rip+0x2f42]        # 4010 <puts@plt+0x2fc0>
    10ce:	48 29 fe             	sub    rsi,rdi
    10d1:	48 89 f0             	mov    rax,rsi
    10d4:	48 c1 ee 3f          	shr    rsi,0x3f
    10d8:	48 c1 f8 03          	sar    rax,0x3
    10dc:	48 01 c6             	add    rsi,rax
    10df:	48 d1 fe             	sar    rsi,1
    10e2:	74 14                	je     10f8 <puts@plt+0xa8>
    10e4:	48 8b 05 05 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f05]        # 3ff0 <puts@plt+0x2fa0>
    10eb:	48 85 c0             	test   rax,rax
    10ee:	74 08                	je     10f8 <puts@plt+0xa8>
    10f0:	ff e0                	jmp    rax
    10f2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    10f8:	c3                   	ret    
    10f9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1100:	f3 0f 1e fa          	endbr64 
    1104:	80 3d 05 2f 00 00 00 	cmp    BYTE PTR [rip+0x2f05],0x0        # 4010 <puts@plt+0x2fc0>
    110b:	75 2b                	jne    1138 <puts@plt+0xe8>
    110d:	55                   	push   rbp
    110e:	48 83 3d e2 2e 00 00 	cmp    QWORD PTR [rip+0x2ee2],0x0        # 3ff8 <puts@plt+0x2fa8>
    1115:	00 
    1116:	48 89 e5             	mov    rbp,rsp
    1119:	74 0c                	je     1127 <puts@plt+0xd7>
    111b:	48 8b 3d e6 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2ee6]        # 4008 <puts@plt+0x2fb8>
    1122:	e8 19 ff ff ff       	call   1040 <__cxa_finalize@plt>
    1127:	e8 64 ff ff ff       	call   1090 <puts@plt+0x40>
    112c:	c6 05 dd 2e 00 00 01 	mov    BYTE PTR [rip+0x2edd],0x1        # 4010 <puts@plt+0x2fc0>
    1133:	5d                   	pop    rbp
    1134:	c3                   	ret    
    1135:	0f 1f 00             	nop    DWORD PTR [rax]
    1138:	c3                   	ret    
    1139:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1140:	f3 0f 1e fa          	endbr64 
    1144:	e9 77 ff ff ff       	jmp    10c0 <puts@plt+0x70>
    1149:	f3 0f 1e fa          	endbr64 
    114d:	55                   	push   rbp
    114e:	48 89 e5             	mov    rbp,rsp
    1151:	48 83 ec 10          	sub    rsp,0x10
    1155:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
    1158:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
    115c:	48 8d 3d a1 0e 00 00 	lea    rdi,[rip+0xea1]        # 2004 <puts@plt+0xfb4>
    1163:	e8 e8 fe ff ff       	call   1050 <puts@plt>
    1168:	b8 00 00 00 00       	mov    eax,0x0
    116d:	c9                   	leave  
    116e:	c3                   	ret    
    116f:	90                   	nop
    1170:	f3 0f 1e fa          	endbr64 
    1174:	41 57                	push   r15
    1176:	4c 8d 3d 3b 2c 00 00 	lea    r15,[rip+0x2c3b]        # 3db8 <puts@plt+0x2d68>
    117d:	41 56                	push   r14
    117f:	49 89 d6             	mov    r14,rdx
    1182:	41 55                	push   r13
    1184:	49 89 f5             	mov    r13,rsi
    1187:	41 54                	push   r12
    1189:	41 89 fc             	mov    r12d,edi
    118c:	55                   	push   rbp
    118d:	48 8d 2d 2c 2c 00 00 	lea    rbp,[rip+0x2c2c]        # 3dc0 <puts@plt+0x2d70>
    1194:	53                   	push   rbx
    1195:	4c 29 fd             	sub    rbp,r15
    1198:	48 83 ec 08          	sub    rsp,0x8
    119c:	e8 5f fe ff ff       	call   1000 <__cxa_finalize@plt-0x40>
    11a1:	48 c1 fd 03          	sar    rbp,0x3
    11a5:	74 1f                	je     11c6 <puts@plt+0x176>
    11a7:	31 db                	xor    ebx,ebx
    11a9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    11b0:	4c 89 f2             	mov    rdx,r14
    11b3:	4c 89 ee             	mov    rsi,r13
    11b6:	44 89 e7             	mov    edi,r12d
    11b9:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
    11bd:	48 83 c3 01          	add    rbx,0x1
    11c1:	48 39 dd             	cmp    rbp,rbx
    11c4:	75 ea                	jne    11b0 <puts@plt+0x160>
    11c6:	48 83 c4 08          	add    rsp,0x8
    11ca:	5b                   	pop    rbx
    11cb:	5d                   	pop    rbp
    11cc:	41 5c                	pop    r12
    11ce:	41 5d                	pop    r13
    11d0:	41 5e                	pop    r14
    11d2:	41 5f                	pop    r15
    11d4:	c3                   	ret    
    11d5:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
    11dc:	00 00 00 00 
    11e0:	f3 0f 1e fa          	endbr64 
    11e4:	c3                   	ret    

Disassembly of section .fini:

00000000000011e8 <.fini>:
    11e8:	f3 0f 1e fa          	endbr64 
    11ec:	48 83 ec 08          	sub    rsp,0x8
    11f0:	48 83 c4 08          	add    rsp,0x8
    11f4:	c3                   	ret    

hello_gcc_x64_stripped:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <.init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 d9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd9]        # 3fe8 <puts@plt+0x2f98>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <__cxa_finalize@plt-0x2a>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 9a 2f 00 00    	push   QWORD PTR [rip+0x2f9a]        # 3fc0 <puts@plt+0x2f70>
    1026:	f2 ff 25 9b 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f9b]        # 3fc8 <puts@plt+0x2f78>
    102d:	0f 1f 00             	nop    DWORD PTR [rax]
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <__cxa_finalize@plt-0x20>
    103f:	90                   	nop

Disassembly of section .plt.got:

0000000000001040 <__cxa_finalize@plt>:
    1040:	f3 0f 1e fa          	endbr64 
    1044:	f2 ff 25 ad 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fad]        # 3ff8 <puts@plt+0x2fa8>
    104b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .plt.sec:

0000000000001050 <puts@plt>:
    1050:	f3 0f 1e fa          	endbr64 
    1054:	f2 ff 25 75 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f75]        # 3fd0 <puts@plt+0x2f80>
    105b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000001060 <.text>:
    1060:	f3 0f 1e fa          	endbr64 
    1064:	31 ed                	xor    ebp,ebp
    1066:	49 89 d1             	mov    r9,rdx
    1069:	5e                   	pop    rsi
    106a:	48 89 e2             	mov    rdx,rsp
    106d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    1071:	50                   	push   rax
    1072:	54                   	push   rsp
    1073:	4c 8d 05 66 01 00 00 	lea    r8,[rip+0x166]        # 11e0 <puts@plt+0x190>
    107a:	48 8d 0d ef 00 00 00 	lea    rcx,[rip+0xef]        # 1170 <puts@plt+0x120>
    1081:	48 8d 3d c1 00 00 00 	lea    rdi,[rip+0xc1]        # 1149 <puts@plt+0xf9>
    1088:	ff 15 52 2f 00 00    	call   QWORD PTR [rip+0x2f52]        # 3fe0 <puts@plt+0x2f90>
    108e:	f4                   	hlt    
    108f:	90                   	nop
    1090:	48 8d 3d 79 2f 00 00 	lea    rdi,[rip+0x2f79]        # 4010 <puts@plt+0x2fc0>
    1097:	48 8d 05 72 2f 00 00 	lea    rax,[rip+0x2f72]        # 4010 <puts@plt+0x2fc0>
    109e:	48 39 f8             	cmp    rax,rdi
    10a1:	74 15                	je     10b8 <puts@plt+0x68>
    10a3:	48 8b 05 2e 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f2e]        # 3fd8 <puts@plt+0x2f88>
    10aa:	48 85 c0             	test   rax,rax
    10ad:	74 09                	je     10b8 <puts@plt+0x68>
    10af:	ff e0                	jmp    rax
    10b1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    10b8:	c3                   	ret    
    10b9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    10c0:	48 8d 3d 49 2f 00 00 	lea    rdi,[rip+0x2f49]        # 4010 <puts@plt+0x2fc0>
    10c7:	48 8d 35 42 2f 00 00 	lea    rsi,[rip+0x2f42]        # 4010 <puts@plt+0x2fc0>
    10ce:	48 29 fe             	sub    rsi,rdi
    10d1:	48 89 f0             	mov    rax,rsi
    10d4:	48 c1 ee 3f          	shr    rsi,0x3f
    10d8:	48 c1 f8 03          	sar    rax,0x3
    10dc:	48 01 c6             	add    rsi,rax
    10df:	48 d1 fe             	sar    rsi,1
    10e2:	74 14                	je     10f8 <puts@plt+0xa8>
    10e4:	48 8b 05 05 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f05]        # 3ff0 <puts@plt+0x2fa0>
    10eb:	48 85 c0             	test   rax,rax
    10ee:	74 08                	je     10f8 <puts@plt+0xa8>
    10f0:	ff e0                	jmp    rax
    10f2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    10f8:	c3                   	ret    
    10f9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1100:	f3 0f 1e fa          	endbr64 
    1104:	80 3d 05 2f 00 00 00 	cmp    BYTE PTR [rip+0x2f05],0x0        # 4010 <puts@plt+0x2fc0>
    110b:	75 2b                	jne    1138 <puts@plt+0xe8>
    110d:	55                   	push   rbp
    110e:	48 83 3d e2 2e 00 00 	cmp    QWORD PTR [rip+0x2ee2],0x0        # 3ff8 <puts@plt+0x2fa8>
    1115:	00 
    1116:	48 89 e5             	mov    rbp,rsp
    1119:	74 0c                	je     1127 <puts@plt+0xd7>
    111b:	48 8b 3d e6 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2ee6]        # 4008 <puts@plt+0x2fb8>
    1122:	e8 19 ff ff ff       	call   1040 <__cxa_finalize@plt>
    1127:	e8 64 ff ff ff       	call   1090 <puts@plt+0x40>
    112c:	c6 05 dd 2e 00 00 01 	mov    BYTE PTR [rip+0x2edd],0x1        # 4010 <puts@plt+0x2fc0>
    1133:	5d                   	pop    rbp
    1134:	c3                   	ret    
    1135:	0f 1f 00             	nop    DWORD PTR [rax]
    1138:	c3                   	ret    
    1139:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1140:	f3 0f 1e fa          	endbr64 
    1144:	e9 77 ff ff ff       	jmp    10c0 <puts@plt+0x70>
    1149:	f3 0f 1e fa          	endbr64 
    114d:	55                   	push   rbp
    114e:	48 89 e5             	mov    rbp,rsp
    1151:	48 83 ec 10          	sub    rsp,0x10
    1155:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
    1158:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
    115c:	48 8d 3d a1 0e 00 00 	lea    rdi,[rip+0xea1]        # 2004 <puts@plt+0xfb4>
    1163:	e8 e8 fe ff ff       	call   1050 <puts@plt>
    1168:	b8 00 00 00 00       	mov    eax,0x0
    116d:	c9                   	leave  
    116e:	c3                   	ret    
    116f:	90                   	nop
    1170:	f3 0f 1e fa          	endbr64 
    1174:	41 57                	push   r15
    1176:	4c 8d 3d 3b 2c 00 00 	lea    r15,[rip+0x2c3b]        # 3db8 <puts@plt+0x2d68>
    117d:	41 56                	push   r14
    117f:	49 89 d6             	mov    r14,rdx
    1182:	41 55                	push   r13
    1184:	49 89 f5             	mov    r13,rsi
    1187:	41 54                	push   r12
    1189:	41 89 fc             	mov    r12d,edi
    118c:	55                   	push   rbp
    118d:	48 8d 2d 2c 2c 00 00 	lea    rbp,[rip+0x2c2c]        # 3dc0 <puts@plt+0x2d70>
    1194:	53                   	push   rbx
    1195:	4c 29 fd             	sub    rbp,r15
    1198:	48 83 ec 08          	sub    rsp,0x8
    119c:	e8 5f fe ff ff       	call   1000 <__cxa_finalize@plt-0x40>
    11a1:	48 c1 fd 03          	sar    rbp,0x3
    11a5:	74 1f                	je     11c6 <puts@plt+0x176>
    11a7:	31 db                	xor    ebx,ebx
    11a9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    11b0:	4c 89 f2             	mov    rdx,r14
    11b3:	4c 89 ee             	mov    rsi,r13
    11b6:	44 89 e7             	mov    edi,r12d
    11b9:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
    11bd:	48 83 c3 01          	add    rbx,0x1
    11c1:	48 39 dd             	cmp    rbp,rbx
    11c4:	75 ea                	jne    11b0 <puts@plt+0x160>
    11c6:	48 83 c4 08          	add    rsp,0x8
    11ca:	5b                   	pop    rbx
    11cb:	5d                   	pop    rbp
    11cc:	41 5c                	pop    r12
    11ce:	41 5d                	pop    r13
    11d0:	41 5e                	pop    r14
    11d2:	41 5f                	pop    r15
    11d4:	c3                   	ret    
    11d5:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
    11dc:	00 00 00 00 
    11e0:	f3 0f 1e fa          	endbr64 
    11e4:	c3                   	ret    

Disassembly of section .fini:

00000000000011e8 <.fini>:
    11e8:	f3 0f 1e fa          	endbr64 
    11ec:	48 83 ec 08          	sub    rsp,0x8
    11f0:	48 83 c4 08          	add    rsp,0x8
    11f4:	c3                   	ret    

hello_gcc_x64_stripped:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <.init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 d9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd9]        # 3fe8 <puts@plt+0x2f98>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <__cxa_finalize@plt-0x2a>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 9a 2f 00 00    	push   QWORD PTR [rip+0x2f9a]        # 3fc0 <puts@plt+0x2f70>
    1026:	f2 ff 25 9b 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f9b]        # 3fc8 <puts@plt+0x2f78>
    102d:	0f 1f 00             	nop    DWORD PTR [rax]
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <__cxa_finalize@plt-0x20>
    103f:	90                   	nop

Disassembly of section .plt.got:

0000000000001040 <__cxa_finalize@plt>:
    1040:	f3 0f 1e fa          	endbr64 
    1044:	f2 ff 25 ad 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fad]        # 3ff8 <puts@plt+0x2fa8>
    104b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .plt.sec:

0000000000001050 <puts@plt>:
    1050:	f3 0f 1e fa          	endbr64 
    1054:	f2 ff 25 75 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f75]        # 3fd0 <puts@plt+0x2f80>
    105b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000001060 <.text>:
    1060:	f3 0f 1e fa          	endbr64 
    1064:	31 ed                	xor    ebp,ebp
    1066:	49 89 d1             	mov    r9,rdx
    1069:	5e                   	pop    rsi
    106a:	48 89 e2             	mov    rdx,rsp
    106d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    1071:	50                   	push   rax
    1072:	54                   	push   rsp
    1073:	4c 8d 05 66 01 00 00 	lea    r8,[rip+0x166]        # 11e0 <puts@plt+0x190>
    107a:	48 8d 0d ef 00 00 00 	lea    rcx,[rip+0xef]        # 1170 <puts@plt+0x120>
    1081:	48 8d 3d c1 00 00 00 	lea    rdi,[rip+0xc1]        # 1149 <puts@plt+0xf9>
    1088:	ff 15 52 2f 00 00    	call   QWORD PTR [rip+0x2f52]        # 3fe0 <puts@plt+0x2f90>
    108e:	f4                   	hlt    
    108f:	90                   	nop
    1090:	48 8d 3d 79 2f 00 00 	lea    rdi,[rip+0x2f79]        # 4010 <puts@plt+0x2fc0>
    1097:	48 8d 05 72 2f 00 00 	lea    rax,[rip+0x2f72]        # 4010 <puts@plt+0x2fc0>
    109e:	48 39 f8             	cmp    rax,rdi
    10a1:	74 15                	je     10b8 <puts@plt+0x68>
    10a3:	48 8b 05 2e 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f2e]        # 3fd8 <puts@plt+0x2f88>
    10aa:	48 85 c0             	test   rax,rax
    10ad:	74 09                	je     10b8 <puts@plt+0x68>
    10af:	ff e0                	jmp    rax
    10b1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    10b8:	c3                   	ret    
    10b9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    10c0:	48 8d 3d 49 2f 00 00 	lea    rdi,[rip+0x2f49]        # 4010 <puts@plt+0x2fc0>
    10c7:	48 8d 35 42 2f 00 00 	lea    rsi,[rip+0x2f42]        # 4010 <puts@plt+0x2fc0>
    10ce:	48 29 fe             	sub    rsi,rdi
    10d1:	48 89 f0             	mov    rax,rsi
    10d4:	48 c1 ee 3f          	shr    rsi,0x3f
    10d8:	48 c1 f8 03          	sar    rax,0x3
    10dc:	48 01 c6             	add    rsi,rax
    10df:	48 d1 fe             	sar    rsi,1
    10e2:	74 14                	je     10f8 <puts@plt+0xa8>
    10e4:	48 8b 05 05 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f05]        # 3ff0 <puts@plt+0x2fa0>
    10eb:	48 85 c0             	test   rax,rax
    10ee:	74 08                	je     10f8 <puts@plt+0xa8>
    10f0:	ff e0                	jmp    rax
    10f2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    10f8:	c3                   	ret    
    10f9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1100:	f3 0f 1e fa          	endbr64 
    1104:	80 3d 05 2f 00 00 00 	cmp    BYTE PTR [rip+0x2f05],0x0        # 4010 <puts@plt+0x2fc0>
    110b:	75 2b                	jne    1138 <puts@plt+0xe8>
    110d:	55                   	push   rbp
    110e:	48 83 3d e2 2e 00 00 	cmp    QWORD PTR [rip+0x2ee2],0x0        # 3ff8 <puts@plt+0x2fa8>
    1115:	00 
    1116:	48 89 e5             	mov    rbp,rsp
    1119:	74 0c                	je     1127 <puts@plt+0xd7>
    111b:	48 8b 3d e6 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2ee6]        # 4008 <puts@plt+0x2fb8>
    1122:	e8 19 ff ff ff       	call   1040 <__cxa_finalize@plt>
    1127:	e8 64 ff ff ff       	call   1090 <puts@plt+0x40>
    112c:	c6 05 dd 2e 00 00 01 	mov    BYTE PTR [rip+0x2edd],0x1        # 4010 <puts@plt+0x2fc0>
    1133:	5d                   	pop    rbp
    1134:	c3                   	ret    
    1135:	0f 1f 00             	nop    DWORD PTR [rax]
    1138:	c3                   	ret    
    1139:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1140:	f3 0f 1e fa          	endbr64 
    1144:	e9 77 ff ff ff       	jmp    10c0 <puts@plt+0x70>
    1149:	f3 0f 1e fa          	endbr64 
    114d:	55                   	push   rbp
    114e:	48 89 e5             	mov    rbp,rsp
    1151:	48 83 ec 10          	sub    rsp,0x10
    1155:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
    1158:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
    115c:	48 8d 3d a1 0e 00 00 	lea    rdi,[rip+0xea1]        # 2004 <puts@plt+0xfb4>
    1163:	e8 e8 fe ff ff       	call   1050 <puts@plt>
    1168:	b8 00 00 00 00       	mov    eax,0x0
    116d:	c9                   	leave  
    116e:	c3                   	ret    
    116f:	90                   	nop
    1170:	f3 0f 1e fa          	endbr64 
    1174:	41 57                	push   r15
    1176:	4c 8d 3d 3b 2c 00 00 	lea    r15,[rip+0x2c3b]        # 3db8 <puts@plt+0x2d68>
    117d:	41 56                	push   r14
    117f:	49 89 d6             	mov    r14,rdx
    1182:	41 55                	push   r13
    1184:	49 89 f5             	mov    r13,rsi
    1187:	41 54                	push   r12
    1189:	41 89 fc             	mov    r12d,edi
    118c:	55                   	push   rbp
    118d:	48 8d 2d 2c 2c 00 00 	lea    rbp,[rip+0x2c2c]        # 3dc0 <puts@plt+0x2d70>
    1194:	53                   	push   rbx
    1195:	4c 29 fd             	sub    rbp,r15
    1198:	48 83 ec 08          	sub    rsp,0x8
    119c:	e8 5f fe ff ff       	call   1000 <__cxa_finalize@plt-0x40>
    11a1:	48 c1 fd 03          	sar    rbp,0x3
    11a5:	74 1f                	je     11c6 <puts@plt+0x176>
    11a7:	31 db                	xor    ebx,ebx
    11a9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    11b0:	4c 89 f2             	mov    rdx,r14
    11b3:	4c 89 ee             	mov    rsi,r13
    11b6:	44 89 e7             	mov    edi,r12d
    11b9:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
    11bd:	48 83 c3 01          	add    rbx,0x1
    11c1:	48 39 dd             	cmp    rbp,rbx
    11c4:	75 ea                	jne    11b0 <puts@plt+0x160>
    11c6:	48 83 c4 08          	add    rsp,0x8
    11ca:	5b                   	pop    rbx
    11cb:	5d                   	pop    rbp
    11cc:	41 5c                	pop    r12
    11ce:	41 5d                	pop    r13
    11d0:	41 5e                	pop    r14
    11d2:	41 5f                	pop    r15
    11d4:	c3                   	ret    
    11d5:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
    11dc:	00 00 00 00 
    11e0:	f3 0f 1e fa          	endbr64 
    11e4:	c3                   	ret    

Disassembly of section .fini:

00000000000011e8 <.fini>:
    11e8:	f3 0f 1e fa          	endbr64 
    11ec:	48 83 ec 08          	sub    rsp,0x8
    11f0:	48 83 c4 08          	add    rsp,0x8
    11f4:	c3                   	ret    

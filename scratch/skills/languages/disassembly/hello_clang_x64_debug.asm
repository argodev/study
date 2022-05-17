
hello_clang_x64_debug:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64 
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 e9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fe9]        # 403ff8 <__gmon_start__>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret    

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 e2 2f 00 00    	push   QWORD PTR [rip+0x2fe2]        # 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	ff 25 e4 2f 00 00    	jmp    QWORD PTR [rip+0x2fe4]        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401030 <printf@plt>:
  401030:	ff 25 e2 2f 00 00    	jmp    QWORD PTR [rip+0x2fe2]        # 404018 <printf@GLIBC_2.2.5>
  401036:	68 00 00 00 00       	push   0x0
  40103b:	e9 e0 ff ff ff       	jmp    401020 <.plt>

Disassembly of section .text:

0000000000401040 <_start>:
  401040:	f3 0f 1e fa          	endbr64 
  401044:	31 ed                	xor    ebp,ebp
  401046:	49 89 d1             	mov    r9,rdx
  401049:	5e                   	pop    rsi
  40104a:	48 89 e2             	mov    rdx,rsp
  40104d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401051:	50                   	push   rax
  401052:	54                   	push   rsp
  401053:	49 c7 c0 e0 11 40 00 	mov    r8,0x4011e0
  40105a:	48 c7 c1 70 11 40 00 	mov    rcx,0x401170
  401061:	48 c7 c7 30 11 40 00 	mov    rdi,0x401130
  401068:	ff 15 82 2f 00 00    	call   QWORD PTR [rip+0x2f82]        # 403ff0 <__libc_start_main@GLIBC_2.2.5>
  40106e:	f4                   	hlt    
  40106f:	90                   	nop

0000000000401070 <_dl_relocate_static_pie>:
  401070:	f3 0f 1e fa          	endbr64 
  401074:	c3                   	ret    
  401075:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40107c:	00 00 00 
  40107f:	90                   	nop

0000000000401080 <deregister_tm_clones>:
  401080:	b8 30 40 40 00       	mov    eax,0x404030
  401085:	48 3d 30 40 40 00    	cmp    rax,0x404030
  40108b:	74 13                	je     4010a0 <deregister_tm_clones+0x20>
  40108d:	b8 00 00 00 00       	mov    eax,0x0
  401092:	48 85 c0             	test   rax,rax
  401095:	74 09                	je     4010a0 <deregister_tm_clones+0x20>
  401097:	bf 30 40 40 00       	mov    edi,0x404030
  40109c:	ff e0                	jmp    rax
  40109e:	66 90                	xchg   ax,ax
  4010a0:	c3                   	ret    
  4010a1:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4010a8:	00 00 00 00 
  4010ac:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004010b0 <register_tm_clones>:
  4010b0:	be 30 40 40 00       	mov    esi,0x404030
  4010b5:	48 81 ee 30 40 40 00 	sub    rsi,0x404030
  4010bc:	48 89 f0             	mov    rax,rsi
  4010bf:	48 c1 ee 3f          	shr    rsi,0x3f
  4010c3:	48 c1 f8 03          	sar    rax,0x3
  4010c7:	48 01 c6             	add    rsi,rax
  4010ca:	48 d1 fe             	sar    rsi,1
  4010cd:	74 11                	je     4010e0 <register_tm_clones+0x30>
  4010cf:	b8 00 00 00 00       	mov    eax,0x0
  4010d4:	48 85 c0             	test   rax,rax
  4010d7:	74 07                	je     4010e0 <register_tm_clones+0x30>
  4010d9:	bf 30 40 40 00       	mov    edi,0x404030
  4010de:	ff e0                	jmp    rax
  4010e0:	c3                   	ret    
  4010e1:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4010e8:	00 00 00 00 
  4010ec:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004010f0 <__do_global_dtors_aux>:
  4010f0:	f3 0f 1e fa          	endbr64 
  4010f4:	80 3d 35 2f 00 00 00 	cmp    BYTE PTR [rip+0x2f35],0x0        # 404030 <__TMC_END__>
  4010fb:	75 13                	jne    401110 <__do_global_dtors_aux+0x20>
  4010fd:	55                   	push   rbp
  4010fe:	48 89 e5             	mov    rbp,rsp
  401101:	e8 7a ff ff ff       	call   401080 <deregister_tm_clones>
  401106:	c6 05 23 2f 00 00 01 	mov    BYTE PTR [rip+0x2f23],0x1        # 404030 <__TMC_END__>
  40110d:	5d                   	pop    rbp
  40110e:	c3                   	ret    
  40110f:	90                   	nop
  401110:	c3                   	ret    
  401111:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  401118:	00 00 00 00 
  40111c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401120 <frame_dummy>:
  401120:	f3 0f 1e fa          	endbr64 
  401124:	eb 8a                	jmp    4010b0 <register_tm_clones>
  401126:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40112d:	00 00 00 

0000000000401130 <main>:
  401130:	55                   	push   rbp
  401131:	48 89 e5             	mov    rbp,rsp
  401134:	48 83 ec 20          	sub    rsp,0x20
  401138:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
  40113f:	89 7d f8             	mov    DWORD PTR [rbp-0x8],edi
  401142:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
  401146:	48 bf 04 20 40 00 00 	movabs rdi,0x402004
  40114d:	00 00 00 
  401150:	b0 00                	mov    al,0x0
  401152:	e8 d9 fe ff ff       	call   401030 <printf@plt>
  401157:	31 c9                	xor    ecx,ecx
  401159:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
  40115c:	89 c8                	mov    eax,ecx
  40115e:	48 83 c4 20          	add    rsp,0x20
  401162:	5d                   	pop    rbp
  401163:	c3                   	ret    
  401164:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40116b:	00 00 00 
  40116e:	66 90                	xchg   ax,ax

0000000000401170 <__libc_csu_init>:
  401170:	f3 0f 1e fa          	endbr64 
  401174:	41 57                	push   r15
  401176:	4c 8d 3d 93 2c 00 00 	lea    r15,[rip+0x2c93]        # 403e10 <__frame_dummy_init_array_entry>
  40117d:	41 56                	push   r14
  40117f:	49 89 d6             	mov    r14,rdx
  401182:	41 55                	push   r13
  401184:	49 89 f5             	mov    r13,rsi
  401187:	41 54                	push   r12
  401189:	41 89 fc             	mov    r12d,edi
  40118c:	55                   	push   rbp
  40118d:	48 8d 2d 84 2c 00 00 	lea    rbp,[rip+0x2c84]        # 403e18 <__do_global_dtors_aux_fini_array_entry>
  401194:	53                   	push   rbx
  401195:	4c 29 fd             	sub    rbp,r15
  401198:	48 83 ec 08          	sub    rsp,0x8
  40119c:	e8 5f fe ff ff       	call   401000 <_init>
  4011a1:	48 c1 fd 03          	sar    rbp,0x3
  4011a5:	74 1f                	je     4011c6 <__libc_csu_init+0x56>
  4011a7:	31 db                	xor    ebx,ebx
  4011a9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  4011b0:	4c 89 f2             	mov    rdx,r14
  4011b3:	4c 89 ee             	mov    rsi,r13
  4011b6:	44 89 e7             	mov    edi,r12d
  4011b9:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
  4011bd:	48 83 c3 01          	add    rbx,0x1
  4011c1:	48 39 dd             	cmp    rbp,rbx
  4011c4:	75 ea                	jne    4011b0 <__libc_csu_init+0x40>
  4011c6:	48 83 c4 08          	add    rsp,0x8
  4011ca:	5b                   	pop    rbx
  4011cb:	5d                   	pop    rbp
  4011cc:	41 5c                	pop    r12
  4011ce:	41 5d                	pop    r13
  4011d0:	41 5e                	pop    r14
  4011d2:	41 5f                	pop    r15
  4011d4:	c3                   	ret    
  4011d5:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4011dc:	00 00 00 00 

00000000004011e0 <__libc_csu_fini>:
  4011e0:	f3 0f 1e fa          	endbr64 
  4011e4:	c3                   	ret    

Disassembly of section .fini:

00000000004011e8 <_fini>:
  4011e8:	f3 0f 1e fa          	endbr64 
  4011ec:	48 83 ec 08          	sub    rsp,0x8
  4011f0:	48 83 c4 08          	add    rsp,0x8
  4011f4:	c3                   	ret    

hello_clang_x64_debug:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64 
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 e9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fe9]        # 403ff8 <__gmon_start__>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret    

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 e2 2f 00 00    	push   QWORD PTR [rip+0x2fe2]        # 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	ff 25 e4 2f 00 00    	jmp    QWORD PTR [rip+0x2fe4]        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401030 <printf@plt>:
  401030:	ff 25 e2 2f 00 00    	jmp    QWORD PTR [rip+0x2fe2]        # 404018 <printf@GLIBC_2.2.5>
  401036:	68 00 00 00 00       	push   0x0
  40103b:	e9 e0 ff ff ff       	jmp    401020 <.plt>

Disassembly of section .text:

0000000000401040 <_start>:
  401040:	f3 0f 1e fa          	endbr64 
  401044:	31 ed                	xor    ebp,ebp
  401046:	49 89 d1             	mov    r9,rdx
  401049:	5e                   	pop    rsi
  40104a:	48 89 e2             	mov    rdx,rsp
  40104d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401051:	50                   	push   rax
  401052:	54                   	push   rsp
  401053:	49 c7 c0 e0 11 40 00 	mov    r8,0x4011e0
  40105a:	48 c7 c1 70 11 40 00 	mov    rcx,0x401170
  401061:	48 c7 c7 30 11 40 00 	mov    rdi,0x401130
  401068:	ff 15 82 2f 00 00    	call   QWORD PTR [rip+0x2f82]        # 403ff0 <__libc_start_main@GLIBC_2.2.5>
  40106e:	f4                   	hlt    
  40106f:	90                   	nop

0000000000401070 <_dl_relocate_static_pie>:
  401070:	f3 0f 1e fa          	endbr64 
  401074:	c3                   	ret    
  401075:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40107c:	00 00 00 
  40107f:	90                   	nop

0000000000401080 <deregister_tm_clones>:
  401080:	b8 30 40 40 00       	mov    eax,0x404030
  401085:	48 3d 30 40 40 00    	cmp    rax,0x404030
  40108b:	74 13                	je     4010a0 <deregister_tm_clones+0x20>
  40108d:	b8 00 00 00 00       	mov    eax,0x0
  401092:	48 85 c0             	test   rax,rax
  401095:	74 09                	je     4010a0 <deregister_tm_clones+0x20>
  401097:	bf 30 40 40 00       	mov    edi,0x404030
  40109c:	ff e0                	jmp    rax
  40109e:	66 90                	xchg   ax,ax
  4010a0:	c3                   	ret    
  4010a1:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4010a8:	00 00 00 00 
  4010ac:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004010b0 <register_tm_clones>:
  4010b0:	be 30 40 40 00       	mov    esi,0x404030
  4010b5:	48 81 ee 30 40 40 00 	sub    rsi,0x404030
  4010bc:	48 89 f0             	mov    rax,rsi
  4010bf:	48 c1 ee 3f          	shr    rsi,0x3f
  4010c3:	48 c1 f8 03          	sar    rax,0x3
  4010c7:	48 01 c6             	add    rsi,rax
  4010ca:	48 d1 fe             	sar    rsi,1
  4010cd:	74 11                	je     4010e0 <register_tm_clones+0x30>
  4010cf:	b8 00 00 00 00       	mov    eax,0x0
  4010d4:	48 85 c0             	test   rax,rax
  4010d7:	74 07                	je     4010e0 <register_tm_clones+0x30>
  4010d9:	bf 30 40 40 00       	mov    edi,0x404030
  4010de:	ff e0                	jmp    rax
  4010e0:	c3                   	ret    
  4010e1:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4010e8:	00 00 00 00 
  4010ec:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004010f0 <__do_global_dtors_aux>:
  4010f0:	f3 0f 1e fa          	endbr64 
  4010f4:	80 3d 35 2f 00 00 00 	cmp    BYTE PTR [rip+0x2f35],0x0        # 404030 <__TMC_END__>
  4010fb:	75 13                	jne    401110 <__do_global_dtors_aux+0x20>
  4010fd:	55                   	push   rbp
  4010fe:	48 89 e5             	mov    rbp,rsp
  401101:	e8 7a ff ff ff       	call   401080 <deregister_tm_clones>
  401106:	c6 05 23 2f 00 00 01 	mov    BYTE PTR [rip+0x2f23],0x1        # 404030 <__TMC_END__>
  40110d:	5d                   	pop    rbp
  40110e:	c3                   	ret    
  40110f:	90                   	nop
  401110:	c3                   	ret    
  401111:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  401118:	00 00 00 00 
  40111c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401120 <frame_dummy>:
  401120:	f3 0f 1e fa          	endbr64 
  401124:	eb 8a                	jmp    4010b0 <register_tm_clones>
  401126:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40112d:	00 00 00 

0000000000401130 <main>:
  401130:	55                   	push   rbp
  401131:	48 89 e5             	mov    rbp,rsp
  401134:	48 83 ec 20          	sub    rsp,0x20
  401138:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
  40113f:	89 7d f8             	mov    DWORD PTR [rbp-0x8],edi
  401142:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
  401146:	48 bf 04 20 40 00 00 	movabs rdi,0x402004
  40114d:	00 00 00 
  401150:	b0 00                	mov    al,0x0
  401152:	e8 d9 fe ff ff       	call   401030 <printf@plt>
  401157:	31 c9                	xor    ecx,ecx
  401159:	89 45 ec             	mov    DWORD PTR [rbp-0x14],eax
  40115c:	89 c8                	mov    eax,ecx
  40115e:	48 83 c4 20          	add    rsp,0x20
  401162:	5d                   	pop    rbp
  401163:	c3                   	ret    
  401164:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40116b:	00 00 00 
  40116e:	66 90                	xchg   ax,ax

0000000000401170 <__libc_csu_init>:
  401170:	f3 0f 1e fa          	endbr64 
  401174:	41 57                	push   r15
  401176:	4c 8d 3d 93 2c 00 00 	lea    r15,[rip+0x2c93]        # 403e10 <__frame_dummy_init_array_entry>
  40117d:	41 56                	push   r14
  40117f:	49 89 d6             	mov    r14,rdx
  401182:	41 55                	push   r13
  401184:	49 89 f5             	mov    r13,rsi
  401187:	41 54                	push   r12
  401189:	41 89 fc             	mov    r12d,edi
  40118c:	55                   	push   rbp
  40118d:	48 8d 2d 84 2c 00 00 	lea    rbp,[rip+0x2c84]        # 403e18 <__do_global_dtors_aux_fini_array_entry>
  401194:	53                   	push   rbx
  401195:	4c 29 fd             	sub    rbp,r15
  401198:	48 83 ec 08          	sub    rsp,0x8
  40119c:	e8 5f fe ff ff       	call   401000 <_init>
  4011a1:	48 c1 fd 03          	sar    rbp,0x3
  4011a5:	74 1f                	je     4011c6 <__libc_csu_init+0x56>
  4011a7:	31 db                	xor    ebx,ebx
  4011a9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  4011b0:	4c 89 f2             	mov    rdx,r14
  4011b3:	4c 89 ee             	mov    rsi,r13
  4011b6:	44 89 e7             	mov    edi,r12d
  4011b9:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
  4011bd:	48 83 c3 01          	add    rbx,0x1
  4011c1:	48 39 dd             	cmp    rbp,rbx
  4011c4:	75 ea                	jne    4011b0 <__libc_csu_init+0x40>
  4011c6:	48 83 c4 08          	add    rsp,0x8
  4011ca:	5b                   	pop    rbx
  4011cb:	5d                   	pop    rbp
  4011cc:	41 5c                	pop    r12
  4011ce:	41 5d                	pop    r13
  4011d0:	41 5e                	pop    r14
  4011d2:	41 5f                	pop    r15
  4011d4:	c3                   	ret    
  4011d5:	66 66 2e 0f 1f 84 00 	data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4011dc:	00 00 00 00 

00000000004011e0 <__libc_csu_fini>:
  4011e0:	f3 0f 1e fa          	endbr64 
  4011e4:	c3                   	ret    

Disassembly of section .fini:

00000000004011e8 <_fini>:
  4011e8:	f3 0f 1e fa          	endbr64 
  4011ec:	48 83 ec 08          	sub    rsp,0x8
  4011f0:	48 83 c4 08          	add    rsp,0x8
  4011f4:	c3                   	ret    


hello_clang_x32_debug:     file format elf32-i386


Disassembly of section .init:

08049000 <_init>:
 8049000:	f3 0f 1e fb          	endbr32 
 8049004:	53                   	push   ebx
 8049005:	83 ec 08             	sub    esp,0x8
 8049008:	e8 a3 00 00 00       	call   80490b0 <__x86.get_pc_thunk.bx>
 804900d:	81 c3 f3 2f 00 00    	add    ebx,0x2ff3
 8049013:	8b 83 fc ff ff ff    	mov    eax,DWORD PTR [ebx-0x4]
 8049019:	85 c0                	test   eax,eax
 804901b:	74 02                	je     804901f <_init+0x1f>
 804901d:	ff d0                	call   eax
 804901f:	83 c4 08             	add    esp,0x8
 8049022:	5b                   	pop    ebx
 8049023:	c3                   	ret    

Disassembly of section .plt:

08049030 <.plt>:
 8049030:	ff 35 04 c0 04 08    	push   DWORD PTR ds:0x804c004
 8049036:	ff 25 08 c0 04 08    	jmp    DWORD PTR ds:0x804c008
 804903c:	00 00                	add    BYTE PTR [eax],al
	...

08049040 <printf@plt>:
 8049040:	ff 25 0c c0 04 08    	jmp    DWORD PTR ds:0x804c00c
 8049046:	68 00 00 00 00       	push   0x0
 804904b:	e9 e0 ff ff ff       	jmp    8049030 <.plt>

08049050 <__libc_start_main@plt>:
 8049050:	ff 25 10 c0 04 08    	jmp    DWORD PTR ds:0x804c010
 8049056:	68 08 00 00 00       	push   0x8
 804905b:	e9 d0 ff ff ff       	jmp    8049030 <.plt>

Disassembly of section .text:

08049060 <_start>:
 8049060:	f3 0f 1e fb          	endbr32 
 8049064:	31 ed                	xor    ebp,ebp
 8049066:	5e                   	pop    esi
 8049067:	89 e1                	mov    ecx,esp
 8049069:	83 e4 f0             	and    esp,0xfffffff0
 804906c:	50                   	push   eax
 804906d:	54                   	push   esp
 804906e:	52                   	push   edx
 804906f:	e8 23 00 00 00       	call   8049097 <_start+0x37>
 8049074:	81 c3 8c 2f 00 00    	add    ebx,0x2f8c
 804907a:	8d 83 30 d2 ff ff    	lea    eax,[ebx-0x2dd0]
 8049080:	50                   	push   eax
 8049081:	8d 83 c0 d1 ff ff    	lea    eax,[ebx-0x2e40]
 8049087:	50                   	push   eax
 8049088:	51                   	push   ecx
 8049089:	56                   	push   esi
 804908a:	c7 c0 80 91 04 08    	mov    eax,0x8049180
 8049090:	50                   	push   eax
 8049091:	e8 ba ff ff ff       	call   8049050 <__libc_start_main@plt>
 8049096:	f4                   	hlt    
 8049097:	8b 1c 24             	mov    ebx,DWORD PTR [esp]
 804909a:	c3                   	ret    
 804909b:	66 90                	xchg   ax,ax
 804909d:	66 90                	xchg   ax,ax
 804909f:	90                   	nop

080490a0 <_dl_relocate_static_pie>:
 80490a0:	f3 0f 1e fb          	endbr32 
 80490a4:	c3                   	ret    
 80490a5:	66 90                	xchg   ax,ax
 80490a7:	66 90                	xchg   ax,ax
 80490a9:	66 90                	xchg   ax,ax
 80490ab:	66 90                	xchg   ax,ax
 80490ad:	66 90                	xchg   ax,ax
 80490af:	90                   	nop

080490b0 <__x86.get_pc_thunk.bx>:
 80490b0:	8b 1c 24             	mov    ebx,DWORD PTR [esp]
 80490b3:	c3                   	ret    
 80490b4:	66 90                	xchg   ax,ax
 80490b6:	66 90                	xchg   ax,ax
 80490b8:	66 90                	xchg   ax,ax
 80490ba:	66 90                	xchg   ax,ax
 80490bc:	66 90                	xchg   ax,ax
 80490be:	66 90                	xchg   ax,ax

080490c0 <deregister_tm_clones>:
 80490c0:	b8 1c c0 04 08       	mov    eax,0x804c01c
 80490c5:	3d 1c c0 04 08       	cmp    eax,0x804c01c
 80490ca:	74 24                	je     80490f0 <deregister_tm_clones+0x30>
 80490cc:	b8 00 00 00 00       	mov    eax,0x0
 80490d1:	85 c0                	test   eax,eax
 80490d3:	74 1b                	je     80490f0 <deregister_tm_clones+0x30>
 80490d5:	55                   	push   ebp
 80490d6:	89 e5                	mov    ebp,esp
 80490d8:	83 ec 14             	sub    esp,0x14
 80490db:	68 1c c0 04 08       	push   0x804c01c
 80490e0:	ff d0                	call   eax
 80490e2:	83 c4 10             	add    esp,0x10
 80490e5:	c9                   	leave  
 80490e6:	c3                   	ret    
 80490e7:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 80490ee:	66 90                	xchg   ax,ax
 80490f0:	c3                   	ret    
 80490f1:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 80490f8:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 80490ff:	90                   	nop

08049100 <register_tm_clones>:
 8049100:	b8 1c c0 04 08       	mov    eax,0x804c01c
 8049105:	2d 1c c0 04 08       	sub    eax,0x804c01c
 804910a:	89 c2                	mov    edx,eax
 804910c:	c1 e8 1f             	shr    eax,0x1f
 804910f:	c1 fa 02             	sar    edx,0x2
 8049112:	01 d0                	add    eax,edx
 8049114:	d1 f8                	sar    eax,1
 8049116:	74 20                	je     8049138 <register_tm_clones+0x38>
 8049118:	ba 00 00 00 00       	mov    edx,0x0
 804911d:	85 d2                	test   edx,edx
 804911f:	74 17                	je     8049138 <register_tm_clones+0x38>
 8049121:	55                   	push   ebp
 8049122:	89 e5                	mov    ebp,esp
 8049124:	83 ec 10             	sub    esp,0x10
 8049127:	50                   	push   eax
 8049128:	68 1c c0 04 08       	push   0x804c01c
 804912d:	ff d2                	call   edx
 804912f:	83 c4 10             	add    esp,0x10
 8049132:	c9                   	leave  
 8049133:	c3                   	ret    
 8049134:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
 8049138:	c3                   	ret    
 8049139:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]

08049140 <__do_global_dtors_aux>:
 8049140:	f3 0f 1e fb          	endbr32 
 8049144:	80 3d 1c c0 04 08 00 	cmp    BYTE PTR ds:0x804c01c,0x0
 804914b:	75 1b                	jne    8049168 <__do_global_dtors_aux+0x28>
 804914d:	55                   	push   ebp
 804914e:	89 e5                	mov    ebp,esp
 8049150:	83 ec 08             	sub    esp,0x8
 8049153:	e8 68 ff ff ff       	call   80490c0 <deregister_tm_clones>
 8049158:	c6 05 1c c0 04 08 01 	mov    BYTE PTR ds:0x804c01c,0x1
 804915f:	c9                   	leave  
 8049160:	c3                   	ret    
 8049161:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 8049168:	c3                   	ret    
 8049169:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]

08049170 <frame_dummy>:
 8049170:	f3 0f 1e fb          	endbr32 
 8049174:	eb 8a                	jmp    8049100 <register_tm_clones>
 8049176:	66 90                	xchg   ax,ax
 8049178:	66 90                	xchg   ax,ax
 804917a:	66 90                	xchg   ax,ax
 804917c:	66 90                	xchg   ax,ax
 804917e:	66 90                	xchg   ax,ax

08049180 <main>:
 8049180:	55                   	push   ebp
 8049181:	89 e5                	mov    ebp,esp
 8049183:	83 ec 18             	sub    esp,0x18
 8049186:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
 8049189:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
 804918c:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [ebp-0x4],0x0
 8049193:	8d 15 08 a0 04 08    	lea    edx,ds:0x804a008
 8049199:	89 14 24             	mov    DWORD PTR [esp],edx
 804919c:	89 45 f8             	mov    DWORD PTR [ebp-0x8],eax
 804919f:	89 4d f4             	mov    DWORD PTR [ebp-0xc],ecx
 80491a2:	e8 99 fe ff ff       	call   8049040 <printf@plt>
 80491a7:	31 c9                	xor    ecx,ecx
 80491a9:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
 80491ac:	89 c8                	mov    eax,ecx
 80491ae:	83 c4 18             	add    esp,0x18
 80491b1:	5d                   	pop    ebp
 80491b2:	c3                   	ret    
 80491b3:	66 90                	xchg   ax,ax
 80491b5:	66 90                	xchg   ax,ax
 80491b7:	66 90                	xchg   ax,ax
 80491b9:	66 90                	xchg   ax,ax
 80491bb:	66 90                	xchg   ax,ax
 80491bd:	66 90                	xchg   ax,ax
 80491bf:	90                   	nop

080491c0 <__libc_csu_init>:
 80491c0:	f3 0f 1e fb          	endbr32 
 80491c4:	55                   	push   ebp
 80491c5:	e8 6b 00 00 00       	call   8049235 <__x86.get_pc_thunk.bp>
 80491ca:	81 c5 36 2e 00 00    	add    ebp,0x2e36
 80491d0:	57                   	push   edi
 80491d1:	56                   	push   esi
 80491d2:	53                   	push   ebx
 80491d3:	83 ec 0c             	sub    esp,0xc
 80491d6:	89 eb                	mov    ebx,ebp
 80491d8:	8b 7c 24 28          	mov    edi,DWORD PTR [esp+0x28]
 80491dc:	e8 1f fe ff ff       	call   8049000 <_init>
 80491e1:	8d 9d 10 ff ff ff    	lea    ebx,[ebp-0xf0]
 80491e7:	8d 85 0c ff ff ff    	lea    eax,[ebp-0xf4]
 80491ed:	29 c3                	sub    ebx,eax
 80491ef:	c1 fb 02             	sar    ebx,0x2
 80491f2:	74 29                	je     804921d <__libc_csu_init+0x5d>
 80491f4:	31 f6                	xor    esi,esi
 80491f6:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 80491fd:	8d 76 00             	lea    esi,[esi+0x0]
 8049200:	83 ec 04             	sub    esp,0x4
 8049203:	57                   	push   edi
 8049204:	ff 74 24 2c          	push   DWORD PTR [esp+0x2c]
 8049208:	ff 74 24 2c          	push   DWORD PTR [esp+0x2c]
 804920c:	ff 94 b5 0c ff ff ff 	call   DWORD PTR [ebp+esi*4-0xf4]
 8049213:	83 c6 01             	add    esi,0x1
 8049216:	83 c4 10             	add    esp,0x10
 8049219:	39 f3                	cmp    ebx,esi
 804921b:	75 e3                	jne    8049200 <__libc_csu_init+0x40>
 804921d:	83 c4 0c             	add    esp,0xc
 8049220:	5b                   	pop    ebx
 8049221:	5e                   	pop    esi
 8049222:	5f                   	pop    edi
 8049223:	5d                   	pop    ebp
 8049224:	c3                   	ret    
 8049225:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 804922c:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]

08049230 <__libc_csu_fini>:
 8049230:	f3 0f 1e fb          	endbr32 
 8049234:	c3                   	ret    

08049235 <__x86.get_pc_thunk.bp>:
 8049235:	8b 2c 24             	mov    ebp,DWORD PTR [esp]
 8049238:	c3                   	ret    

Disassembly of section .fini:

0804923c <_fini>:
 804923c:	f3 0f 1e fb          	endbr32 
 8049240:	53                   	push   ebx
 8049241:	83 ec 08             	sub    esp,0x8
 8049244:	e8 67 fe ff ff       	call   80490b0 <__x86.get_pc_thunk.bx>
 8049249:	81 c3 b7 2d 00 00    	add    ebx,0x2db7
 804924f:	83 c4 08             	add    esp,0x8
 8049252:	5b                   	pop    ebx
 8049253:	c3                   	ret    

hello_clang_x32_debug:     file format elf32-i386


Disassembly of section .init:

08049000 <_init>:
 8049000:	f3 0f 1e fb          	endbr32 
 8049004:	53                   	push   ebx
 8049005:	83 ec 08             	sub    esp,0x8
 8049008:	e8 a3 00 00 00       	call   80490b0 <__x86.get_pc_thunk.bx>
 804900d:	81 c3 f3 2f 00 00    	add    ebx,0x2ff3
 8049013:	8b 83 fc ff ff ff    	mov    eax,DWORD PTR [ebx-0x4]
 8049019:	85 c0                	test   eax,eax
 804901b:	74 02                	je     804901f <_init+0x1f>
 804901d:	ff d0                	call   eax
 804901f:	83 c4 08             	add    esp,0x8
 8049022:	5b                   	pop    ebx
 8049023:	c3                   	ret    

Disassembly of section .plt:

08049030 <.plt>:
 8049030:	ff 35 04 c0 04 08    	push   DWORD PTR ds:0x804c004
 8049036:	ff 25 08 c0 04 08    	jmp    DWORD PTR ds:0x804c008
 804903c:	00 00                	add    BYTE PTR [eax],al
	...

08049040 <printf@plt>:
 8049040:	ff 25 0c c0 04 08    	jmp    DWORD PTR ds:0x804c00c
 8049046:	68 00 00 00 00       	push   0x0
 804904b:	e9 e0 ff ff ff       	jmp    8049030 <.plt>

08049050 <__libc_start_main@plt>:
 8049050:	ff 25 10 c0 04 08    	jmp    DWORD PTR ds:0x804c010
 8049056:	68 08 00 00 00       	push   0x8
 804905b:	e9 d0 ff ff ff       	jmp    8049030 <.plt>

Disassembly of section .text:

08049060 <_start>:
 8049060:	f3 0f 1e fb          	endbr32 
 8049064:	31 ed                	xor    ebp,ebp
 8049066:	5e                   	pop    esi
 8049067:	89 e1                	mov    ecx,esp
 8049069:	83 e4 f0             	and    esp,0xfffffff0
 804906c:	50                   	push   eax
 804906d:	54                   	push   esp
 804906e:	52                   	push   edx
 804906f:	e8 23 00 00 00       	call   8049097 <_start+0x37>
 8049074:	81 c3 8c 2f 00 00    	add    ebx,0x2f8c
 804907a:	8d 83 30 d2 ff ff    	lea    eax,[ebx-0x2dd0]
 8049080:	50                   	push   eax
 8049081:	8d 83 c0 d1 ff ff    	lea    eax,[ebx-0x2e40]
 8049087:	50                   	push   eax
 8049088:	51                   	push   ecx
 8049089:	56                   	push   esi
 804908a:	c7 c0 80 91 04 08    	mov    eax,0x8049180
 8049090:	50                   	push   eax
 8049091:	e8 ba ff ff ff       	call   8049050 <__libc_start_main@plt>
 8049096:	f4                   	hlt    
 8049097:	8b 1c 24             	mov    ebx,DWORD PTR [esp]
 804909a:	c3                   	ret    
 804909b:	66 90                	xchg   ax,ax
 804909d:	66 90                	xchg   ax,ax
 804909f:	90                   	nop

080490a0 <_dl_relocate_static_pie>:
 80490a0:	f3 0f 1e fb          	endbr32 
 80490a4:	c3                   	ret    
 80490a5:	66 90                	xchg   ax,ax
 80490a7:	66 90                	xchg   ax,ax
 80490a9:	66 90                	xchg   ax,ax
 80490ab:	66 90                	xchg   ax,ax
 80490ad:	66 90                	xchg   ax,ax
 80490af:	90                   	nop

080490b0 <__x86.get_pc_thunk.bx>:
 80490b0:	8b 1c 24             	mov    ebx,DWORD PTR [esp]
 80490b3:	c3                   	ret    
 80490b4:	66 90                	xchg   ax,ax
 80490b6:	66 90                	xchg   ax,ax
 80490b8:	66 90                	xchg   ax,ax
 80490ba:	66 90                	xchg   ax,ax
 80490bc:	66 90                	xchg   ax,ax
 80490be:	66 90                	xchg   ax,ax

080490c0 <deregister_tm_clones>:
 80490c0:	b8 1c c0 04 08       	mov    eax,0x804c01c
 80490c5:	3d 1c c0 04 08       	cmp    eax,0x804c01c
 80490ca:	74 24                	je     80490f0 <deregister_tm_clones+0x30>
 80490cc:	b8 00 00 00 00       	mov    eax,0x0
 80490d1:	85 c0                	test   eax,eax
 80490d3:	74 1b                	je     80490f0 <deregister_tm_clones+0x30>
 80490d5:	55                   	push   ebp
 80490d6:	89 e5                	mov    ebp,esp
 80490d8:	83 ec 14             	sub    esp,0x14
 80490db:	68 1c c0 04 08       	push   0x804c01c
 80490e0:	ff d0                	call   eax
 80490e2:	83 c4 10             	add    esp,0x10
 80490e5:	c9                   	leave  
 80490e6:	c3                   	ret    
 80490e7:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 80490ee:	66 90                	xchg   ax,ax
 80490f0:	c3                   	ret    
 80490f1:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 80490f8:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 80490ff:	90                   	nop

08049100 <register_tm_clones>:
 8049100:	b8 1c c0 04 08       	mov    eax,0x804c01c
 8049105:	2d 1c c0 04 08       	sub    eax,0x804c01c
 804910a:	89 c2                	mov    edx,eax
 804910c:	c1 e8 1f             	shr    eax,0x1f
 804910f:	c1 fa 02             	sar    edx,0x2
 8049112:	01 d0                	add    eax,edx
 8049114:	d1 f8                	sar    eax,1
 8049116:	74 20                	je     8049138 <register_tm_clones+0x38>
 8049118:	ba 00 00 00 00       	mov    edx,0x0
 804911d:	85 d2                	test   edx,edx
 804911f:	74 17                	je     8049138 <register_tm_clones+0x38>
 8049121:	55                   	push   ebp
 8049122:	89 e5                	mov    ebp,esp
 8049124:	83 ec 10             	sub    esp,0x10
 8049127:	50                   	push   eax
 8049128:	68 1c c0 04 08       	push   0x804c01c
 804912d:	ff d2                	call   edx
 804912f:	83 c4 10             	add    esp,0x10
 8049132:	c9                   	leave  
 8049133:	c3                   	ret    
 8049134:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
 8049138:	c3                   	ret    
 8049139:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]

08049140 <__do_global_dtors_aux>:
 8049140:	f3 0f 1e fb          	endbr32 
 8049144:	80 3d 1c c0 04 08 00 	cmp    BYTE PTR ds:0x804c01c,0x0
 804914b:	75 1b                	jne    8049168 <__do_global_dtors_aux+0x28>
 804914d:	55                   	push   ebp
 804914e:	89 e5                	mov    ebp,esp
 8049150:	83 ec 08             	sub    esp,0x8
 8049153:	e8 68 ff ff ff       	call   80490c0 <deregister_tm_clones>
 8049158:	c6 05 1c c0 04 08 01 	mov    BYTE PTR ds:0x804c01c,0x1
 804915f:	c9                   	leave  
 8049160:	c3                   	ret    
 8049161:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 8049168:	c3                   	ret    
 8049169:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]

08049170 <frame_dummy>:
 8049170:	f3 0f 1e fb          	endbr32 
 8049174:	eb 8a                	jmp    8049100 <register_tm_clones>
 8049176:	66 90                	xchg   ax,ax
 8049178:	66 90                	xchg   ax,ax
 804917a:	66 90                	xchg   ax,ax
 804917c:	66 90                	xchg   ax,ax
 804917e:	66 90                	xchg   ax,ax

08049180 <main>:
 8049180:	55                   	push   ebp
 8049181:	89 e5                	mov    ebp,esp
 8049183:	83 ec 18             	sub    esp,0x18
 8049186:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
 8049189:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
 804918c:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [ebp-0x4],0x0
 8049193:	8d 15 08 a0 04 08    	lea    edx,ds:0x804a008
 8049199:	89 14 24             	mov    DWORD PTR [esp],edx
 804919c:	89 45 f8             	mov    DWORD PTR [ebp-0x8],eax
 804919f:	89 4d f4             	mov    DWORD PTR [ebp-0xc],ecx
 80491a2:	e8 99 fe ff ff       	call   8049040 <printf@plt>
 80491a7:	31 c9                	xor    ecx,ecx
 80491a9:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
 80491ac:	89 c8                	mov    eax,ecx
 80491ae:	83 c4 18             	add    esp,0x18
 80491b1:	5d                   	pop    ebp
 80491b2:	c3                   	ret    
 80491b3:	66 90                	xchg   ax,ax
 80491b5:	66 90                	xchg   ax,ax
 80491b7:	66 90                	xchg   ax,ax
 80491b9:	66 90                	xchg   ax,ax
 80491bb:	66 90                	xchg   ax,ax
 80491bd:	66 90                	xchg   ax,ax
 80491bf:	90                   	nop

080491c0 <__libc_csu_init>:
 80491c0:	f3 0f 1e fb          	endbr32 
 80491c4:	55                   	push   ebp
 80491c5:	e8 6b 00 00 00       	call   8049235 <__x86.get_pc_thunk.bp>
 80491ca:	81 c5 36 2e 00 00    	add    ebp,0x2e36
 80491d0:	57                   	push   edi
 80491d1:	56                   	push   esi
 80491d2:	53                   	push   ebx
 80491d3:	83 ec 0c             	sub    esp,0xc
 80491d6:	89 eb                	mov    ebx,ebp
 80491d8:	8b 7c 24 28          	mov    edi,DWORD PTR [esp+0x28]
 80491dc:	e8 1f fe ff ff       	call   8049000 <_init>
 80491e1:	8d 9d 10 ff ff ff    	lea    ebx,[ebp-0xf0]
 80491e7:	8d 85 0c ff ff ff    	lea    eax,[ebp-0xf4]
 80491ed:	29 c3                	sub    ebx,eax
 80491ef:	c1 fb 02             	sar    ebx,0x2
 80491f2:	74 29                	je     804921d <__libc_csu_init+0x5d>
 80491f4:	31 f6                	xor    esi,esi
 80491f6:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 80491fd:	8d 76 00             	lea    esi,[esi+0x0]
 8049200:	83 ec 04             	sub    esp,0x4
 8049203:	57                   	push   edi
 8049204:	ff 74 24 2c          	push   DWORD PTR [esp+0x2c]
 8049208:	ff 74 24 2c          	push   DWORD PTR [esp+0x2c]
 804920c:	ff 94 b5 0c ff ff ff 	call   DWORD PTR [ebp+esi*4-0xf4]
 8049213:	83 c6 01             	add    esi,0x1
 8049216:	83 c4 10             	add    esp,0x10
 8049219:	39 f3                	cmp    ebx,esi
 804921b:	75 e3                	jne    8049200 <__libc_csu_init+0x40>
 804921d:	83 c4 0c             	add    esp,0xc
 8049220:	5b                   	pop    ebx
 8049221:	5e                   	pop    esi
 8049222:	5f                   	pop    edi
 8049223:	5d                   	pop    ebp
 8049224:	c3                   	ret    
 8049225:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
 804922c:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]

08049230 <__libc_csu_fini>:
 8049230:	f3 0f 1e fb          	endbr32 
 8049234:	c3                   	ret    

08049235 <__x86.get_pc_thunk.bp>:
 8049235:	8b 2c 24             	mov    ebp,DWORD PTR [esp]
 8049238:	c3                   	ret    

Disassembly of section .fini:

0804923c <_fini>:
 804923c:	f3 0f 1e fb          	endbr32 
 8049240:	53                   	push   ebx
 8049241:	83 ec 08             	sub    esp,0x8
 8049244:	e8 67 fe ff ff       	call   80490b0 <__x86.get_pc_thunk.bx>
 8049249:	81 c3 b7 2d 00 00    	add    ebx,0x2db7
 804924f:	83 c4 08             	add    esp,0x8
 8049252:	5b                   	pop    ebx
 8049253:	c3                   	ret    

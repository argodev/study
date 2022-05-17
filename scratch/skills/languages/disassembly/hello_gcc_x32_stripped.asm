
hello_gcc_x32_stripped:     file format elf32-i386


Disassembly of section .init:

00001000 <.init>:
    1000:	f3 0f 1e fb          	endbr32 
    1004:	53                   	push   ebx
    1005:	83 ec 08             	sub    esp,0x8
    1008:	e8 c3 00 00 00       	call   10d0 <__libc_start_main@plt+0x50>
    100d:	81 c3 cb 2f 00 00    	add    ebx,0x2fcb
    1013:	8b 83 1c 00 00 00    	mov    eax,DWORD PTR [ebx+0x1c]
    1019:	85 c0                	test   eax,eax
    101b:	74 02                	je     101f <__cxa_finalize@plt-0x41>
    101d:	ff d0                	call   eax
    101f:	83 c4 08             	add    esp,0x8
    1022:	5b                   	pop    ebx
    1023:	c3                   	ret    

Disassembly of section .plt:

00001030 <.plt>:
    1030:	ff b3 04 00 00 00    	push   DWORD PTR [ebx+0x4]
    1036:	ff a3 08 00 00 00    	jmp    DWORD PTR [ebx+0x8]
    103c:	0f 1f 40 00          	nop    DWORD PTR [eax+0x0]
    1040:	f3 0f 1e fb          	endbr32 
    1044:	68 00 00 00 00       	push   0x0
    1049:	e9 e2 ff ff ff       	jmp    1030 <__cxa_finalize@plt-0x30>
    104e:	66 90                	xchg   ax,ax
    1050:	f3 0f 1e fb          	endbr32 
    1054:	68 08 00 00 00       	push   0x8
    1059:	e9 d2 ff ff ff       	jmp    1030 <__cxa_finalize@plt-0x30>
    105e:	66 90                	xchg   ax,ax

Disassembly of section .plt.got:

00001060 <__cxa_finalize@plt>:
    1060:	f3 0f 1e fb          	endbr32 
    1064:	ff a3 18 00 00 00    	jmp    DWORD PTR [ebx+0x18]
    106a:	66 0f 1f 44 00 00    	nop    WORD PTR [eax+eax*1+0x0]

Disassembly of section .plt.sec:

00001070 <puts@plt>:
    1070:	f3 0f 1e fb          	endbr32 
    1074:	ff a3 0c 00 00 00    	jmp    DWORD PTR [ebx+0xc]
    107a:	66 0f 1f 44 00 00    	nop    WORD PTR [eax+eax*1+0x0]

00001080 <__libc_start_main@plt>:
    1080:	f3 0f 1e fb          	endbr32 
    1084:	ff a3 10 00 00 00    	jmp    DWORD PTR [ebx+0x10]
    108a:	66 0f 1f 44 00 00    	nop    WORD PTR [eax+eax*1+0x0]

Disassembly of section .text:

00001090 <.text>:
    1090:	f3 0f 1e fb          	endbr32 
    1094:	31 ed                	xor    ebp,ebp
    1096:	5e                   	pop    esi
    1097:	89 e1                	mov    ecx,esp
    1099:	83 e4 f0             	and    esp,0xfffffff0
    109c:	50                   	push   eax
    109d:	54                   	push   esp
    109e:	52                   	push   edx
    109f:	e8 22 00 00 00       	call   10c6 <__libc_start_main@plt+0x46>
    10a4:	81 c3 34 2f 00 00    	add    ebx,0x2f34
    10aa:	8d 83 b8 d2 ff ff    	lea    eax,[ebx-0x2d48]
    10b0:	50                   	push   eax
    10b1:	8d 83 48 d2 ff ff    	lea    eax,[ebx-0x2db8]
    10b7:	50                   	push   eax
    10b8:	51                   	push   ecx
    10b9:	56                   	push   esi
    10ba:	ff b3 20 00 00 00    	push   DWORD PTR [ebx+0x20]
    10c0:	e8 bb ff ff ff       	call   1080 <__libc_start_main@plt>
    10c5:	f4                   	hlt    
    10c6:	8b 1c 24             	mov    ebx,DWORD PTR [esp]
    10c9:	c3                   	ret    
    10ca:	66 90                	xchg   ax,ax
    10cc:	66 90                	xchg   ax,ax
    10ce:	66 90                	xchg   ax,ax
    10d0:	8b 1c 24             	mov    ebx,DWORD PTR [esp]
    10d3:	c3                   	ret    
    10d4:	66 90                	xchg   ax,ax
    10d6:	66 90                	xchg   ax,ax
    10d8:	66 90                	xchg   ax,ax
    10da:	66 90                	xchg   ax,ax
    10dc:	66 90                	xchg   ax,ax
    10de:	66 90                	xchg   ax,ax
    10e0:	e8 e4 00 00 00       	call   11c9 <__libc_start_main@plt+0x149>
    10e5:	81 c2 f3 2e 00 00    	add    edx,0x2ef3
    10eb:	8d 8a 30 00 00 00    	lea    ecx,[edx+0x30]
    10f1:	8d 82 30 00 00 00    	lea    eax,[edx+0x30]
    10f7:	39 c8                	cmp    eax,ecx
    10f9:	74 1d                	je     1118 <__libc_start_main@plt+0x98>
    10fb:	8b 82 14 00 00 00    	mov    eax,DWORD PTR [edx+0x14]
    1101:	85 c0                	test   eax,eax
    1103:	74 13                	je     1118 <__libc_start_main@plt+0x98>
    1105:	55                   	push   ebp
    1106:	89 e5                	mov    ebp,esp
    1108:	83 ec 14             	sub    esp,0x14
    110b:	51                   	push   ecx
    110c:	ff d0                	call   eax
    110e:	83 c4 10             	add    esp,0x10
    1111:	c9                   	leave  
    1112:	c3                   	ret    
    1113:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
    1117:	90                   	nop
    1118:	c3                   	ret    
    1119:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
    1120:	e8 a4 00 00 00       	call   11c9 <__libc_start_main@plt+0x149>
    1125:	81 c2 b3 2e 00 00    	add    edx,0x2eb3
    112b:	55                   	push   ebp
    112c:	89 e5                	mov    ebp,esp
    112e:	53                   	push   ebx
    112f:	8d 8a 30 00 00 00    	lea    ecx,[edx+0x30]
    1135:	8d 82 30 00 00 00    	lea    eax,[edx+0x30]
    113b:	83 ec 04             	sub    esp,0x4
    113e:	29 c8                	sub    eax,ecx
    1140:	89 c3                	mov    ebx,eax
    1142:	c1 e8 1f             	shr    eax,0x1f
    1145:	c1 fb 02             	sar    ebx,0x2
    1148:	01 d8                	add    eax,ebx
    114a:	d1 f8                	sar    eax,1
    114c:	74 14                	je     1162 <__libc_start_main@plt+0xe2>
    114e:	8b 92 24 00 00 00    	mov    edx,DWORD PTR [edx+0x24]
    1154:	85 d2                	test   edx,edx
    1156:	74 0a                	je     1162 <__libc_start_main@plt+0xe2>
    1158:	83 ec 08             	sub    esp,0x8
    115b:	50                   	push   eax
    115c:	51                   	push   ecx
    115d:	ff d2                	call   edx
    115f:	83 c4 10             	add    esp,0x10
    1162:	8b 5d fc             	mov    ebx,DWORD PTR [ebp-0x4]
    1165:	c9                   	leave  
    1166:	c3                   	ret    
    1167:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
    116e:	66 90                	xchg   ax,ax
    1170:	f3 0f 1e fb          	endbr32 
    1174:	55                   	push   ebp
    1175:	89 e5                	mov    ebp,esp
    1177:	53                   	push   ebx
    1178:	e8 53 ff ff ff       	call   10d0 <__libc_start_main@plt+0x50>
    117d:	81 c3 5b 2e 00 00    	add    ebx,0x2e5b
    1183:	83 ec 04             	sub    esp,0x4
    1186:	80 bb 30 00 00 00 00 	cmp    BYTE PTR [ebx+0x30],0x0
    118d:	75 27                	jne    11b6 <__libc_start_main@plt+0x136>
    118f:	8b 83 18 00 00 00    	mov    eax,DWORD PTR [ebx+0x18]
    1195:	85 c0                	test   eax,eax
    1197:	74 11                	je     11aa <__libc_start_main@plt+0x12a>
    1199:	83 ec 0c             	sub    esp,0xc
    119c:	ff b3 2c 00 00 00    	push   DWORD PTR [ebx+0x2c]
    11a2:	e8 b9 fe ff ff       	call   1060 <__cxa_finalize@plt>
    11a7:	83 c4 10             	add    esp,0x10
    11aa:	e8 31 ff ff ff       	call   10e0 <__libc_start_main@plt+0x60>
    11af:	c6 83 30 00 00 00 01 	mov    BYTE PTR [ebx+0x30],0x1
    11b6:	8b 5d fc             	mov    ebx,DWORD PTR [ebp-0x4]
    11b9:	c9                   	leave  
    11ba:	c3                   	ret    
    11bb:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
    11bf:	90                   	nop
    11c0:	f3 0f 1e fb          	endbr32 
    11c4:	e9 57 ff ff ff       	jmp    1120 <__libc_start_main@plt+0xa0>
    11c9:	8b 14 24             	mov    edx,DWORD PTR [esp]
    11cc:	c3                   	ret    
    11cd:	f3 0f 1e fb          	endbr32 
    11d1:	8d 4c 24 04          	lea    ecx,[esp+0x4]
    11d5:	83 e4 f0             	and    esp,0xfffffff0
    11d8:	ff 71 fc             	push   DWORD PTR [ecx-0x4]
    11db:	55                   	push   ebp
    11dc:	89 e5                	mov    ebp,esp
    11de:	53                   	push   ebx
    11df:	51                   	push   ecx
    11e0:	e8 28 00 00 00       	call   120d <__libc_start_main@plt+0x18d>
    11e5:	05 f3 2d 00 00       	add    eax,0x2df3
    11ea:	83 ec 0c             	sub    esp,0xc
    11ed:	8d 90 30 e0 ff ff    	lea    edx,[eax-0x1fd0]
    11f3:	52                   	push   edx
    11f4:	89 c3                	mov    ebx,eax
    11f6:	e8 75 fe ff ff       	call   1070 <puts@plt>
    11fb:	83 c4 10             	add    esp,0x10
    11fe:	b8 00 00 00 00       	mov    eax,0x0
    1203:	8d 65 f8             	lea    esp,[ebp-0x8]
    1206:	59                   	pop    ecx
    1207:	5b                   	pop    ebx
    1208:	5d                   	pop    ebp
    1209:	8d 61 fc             	lea    esp,[ecx-0x4]
    120c:	c3                   	ret    
    120d:	8b 04 24             	mov    eax,DWORD PTR [esp]
    1210:	c3                   	ret    
    1211:	66 90                	xchg   ax,ax
    1213:	66 90                	xchg   ax,ax
    1215:	66 90                	xchg   ax,ax
    1217:	66 90                	xchg   ax,ax
    1219:	66 90                	xchg   ax,ax
    121b:	66 90                	xchg   ax,ax
    121d:	66 90                	xchg   ax,ax
    121f:	90                   	nop
    1220:	f3 0f 1e fb          	endbr32 
    1224:	55                   	push   ebp
    1225:	e8 6b 00 00 00       	call   1295 <__libc_start_main@plt+0x215>
    122a:	81 c5 ae 2d 00 00    	add    ebp,0x2dae
    1230:	57                   	push   edi
    1231:	56                   	push   esi
    1232:	53                   	push   ebx
    1233:	83 ec 0c             	sub    esp,0xc
    1236:	89 eb                	mov    ebx,ebp
    1238:	8b 7c 24 28          	mov    edi,DWORD PTR [esp+0x28]
    123c:	e8 bf fd ff ff       	call   1000 <__cxa_finalize@plt-0x60>
    1241:	8d 9d 04 ff ff ff    	lea    ebx,[ebp-0xfc]
    1247:	8d 85 00 ff ff ff    	lea    eax,[ebp-0x100]
    124d:	29 c3                	sub    ebx,eax
    124f:	c1 fb 02             	sar    ebx,0x2
    1252:	74 29                	je     127d <__libc_start_main@plt+0x1fd>
    1254:	31 f6                	xor    esi,esi
    1256:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
    125d:	8d 76 00             	lea    esi,[esi+0x0]
    1260:	83 ec 04             	sub    esp,0x4
    1263:	57                   	push   edi
    1264:	ff 74 24 2c          	push   DWORD PTR [esp+0x2c]
    1268:	ff 74 24 2c          	push   DWORD PTR [esp+0x2c]
    126c:	ff 94 b5 00 ff ff ff 	call   DWORD PTR [ebp+esi*4-0x100]
    1273:	83 c6 01             	add    esi,0x1
    1276:	83 c4 10             	add    esp,0x10
    1279:	39 f3                	cmp    ebx,esi
    127b:	75 e3                	jne    1260 <__libc_start_main@plt+0x1e0>
    127d:	83 c4 0c             	add    esp,0xc
    1280:	5b                   	pop    ebx
    1281:	5e                   	pop    esi
    1282:	5f                   	pop    edi
    1283:	5d                   	pop    ebp
    1284:	c3                   	ret    
    1285:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
    128c:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
    1290:	f3 0f 1e fb          	endbr32 
    1294:	c3                   	ret    
    1295:	8b 2c 24             	mov    ebp,DWORD PTR [esp]
    1298:	c3                   	ret    

Disassembly of section .fini:

0000129c <.fini>:
    129c:	f3 0f 1e fb          	endbr32 
    12a0:	53                   	push   ebx
    12a1:	83 ec 08             	sub    esp,0x8
    12a4:	e8 27 fe ff ff       	call   10d0 <__libc_start_main@plt+0x50>
    12a9:	81 c3 2f 2d 00 00    	add    ebx,0x2d2f
    12af:	83 c4 08             	add    esp,0x8
    12b2:	5b                   	pop    ebx
    12b3:	c3                   	ret    

hello_gcc_x32_stripped:     file format elf32-i386


Disassembly of section .init:

00001000 <.init>:
    1000:	f3 0f 1e fb          	endbr32 
    1004:	53                   	push   ebx
    1005:	83 ec 08             	sub    esp,0x8
    1008:	e8 c3 00 00 00       	call   10d0 <__libc_start_main@plt+0x50>
    100d:	81 c3 cb 2f 00 00    	add    ebx,0x2fcb
    1013:	8b 83 1c 00 00 00    	mov    eax,DWORD PTR [ebx+0x1c]
    1019:	85 c0                	test   eax,eax
    101b:	74 02                	je     101f <__cxa_finalize@plt-0x41>
    101d:	ff d0                	call   eax
    101f:	83 c4 08             	add    esp,0x8
    1022:	5b                   	pop    ebx
    1023:	c3                   	ret    

Disassembly of section .plt:

00001030 <.plt>:
    1030:	ff b3 04 00 00 00    	push   DWORD PTR [ebx+0x4]
    1036:	ff a3 08 00 00 00    	jmp    DWORD PTR [ebx+0x8]
    103c:	0f 1f 40 00          	nop    DWORD PTR [eax+0x0]
    1040:	f3 0f 1e fb          	endbr32 
    1044:	68 00 00 00 00       	push   0x0
    1049:	e9 e2 ff ff ff       	jmp    1030 <__cxa_finalize@plt-0x30>
    104e:	66 90                	xchg   ax,ax
    1050:	f3 0f 1e fb          	endbr32 
    1054:	68 08 00 00 00       	push   0x8
    1059:	e9 d2 ff ff ff       	jmp    1030 <__cxa_finalize@plt-0x30>
    105e:	66 90                	xchg   ax,ax

Disassembly of section .plt.got:

00001060 <__cxa_finalize@plt>:
    1060:	f3 0f 1e fb          	endbr32 
    1064:	ff a3 18 00 00 00    	jmp    DWORD PTR [ebx+0x18]
    106a:	66 0f 1f 44 00 00    	nop    WORD PTR [eax+eax*1+0x0]

Disassembly of section .plt.sec:

00001070 <puts@plt>:
    1070:	f3 0f 1e fb          	endbr32 
    1074:	ff a3 0c 00 00 00    	jmp    DWORD PTR [ebx+0xc]
    107a:	66 0f 1f 44 00 00    	nop    WORD PTR [eax+eax*1+0x0]

00001080 <__libc_start_main@plt>:
    1080:	f3 0f 1e fb          	endbr32 
    1084:	ff a3 10 00 00 00    	jmp    DWORD PTR [ebx+0x10]
    108a:	66 0f 1f 44 00 00    	nop    WORD PTR [eax+eax*1+0x0]

Disassembly of section .text:

00001090 <.text>:
    1090:	f3 0f 1e fb          	endbr32 
    1094:	31 ed                	xor    ebp,ebp
    1096:	5e                   	pop    esi
    1097:	89 e1                	mov    ecx,esp
    1099:	83 e4 f0             	and    esp,0xfffffff0
    109c:	50                   	push   eax
    109d:	54                   	push   esp
    109e:	52                   	push   edx
    109f:	e8 22 00 00 00       	call   10c6 <__libc_start_main@plt+0x46>
    10a4:	81 c3 34 2f 00 00    	add    ebx,0x2f34
    10aa:	8d 83 b8 d2 ff ff    	lea    eax,[ebx-0x2d48]
    10b0:	50                   	push   eax
    10b1:	8d 83 48 d2 ff ff    	lea    eax,[ebx-0x2db8]
    10b7:	50                   	push   eax
    10b8:	51                   	push   ecx
    10b9:	56                   	push   esi
    10ba:	ff b3 20 00 00 00    	push   DWORD PTR [ebx+0x20]
    10c0:	e8 bb ff ff ff       	call   1080 <__libc_start_main@plt>
    10c5:	f4                   	hlt    
    10c6:	8b 1c 24             	mov    ebx,DWORD PTR [esp]
    10c9:	c3                   	ret    
    10ca:	66 90                	xchg   ax,ax
    10cc:	66 90                	xchg   ax,ax
    10ce:	66 90                	xchg   ax,ax
    10d0:	8b 1c 24             	mov    ebx,DWORD PTR [esp]
    10d3:	c3                   	ret    
    10d4:	66 90                	xchg   ax,ax
    10d6:	66 90                	xchg   ax,ax
    10d8:	66 90                	xchg   ax,ax
    10da:	66 90                	xchg   ax,ax
    10dc:	66 90                	xchg   ax,ax
    10de:	66 90                	xchg   ax,ax
    10e0:	e8 e4 00 00 00       	call   11c9 <__libc_start_main@plt+0x149>
    10e5:	81 c2 f3 2e 00 00    	add    edx,0x2ef3
    10eb:	8d 8a 30 00 00 00    	lea    ecx,[edx+0x30]
    10f1:	8d 82 30 00 00 00    	lea    eax,[edx+0x30]
    10f7:	39 c8                	cmp    eax,ecx
    10f9:	74 1d                	je     1118 <__libc_start_main@plt+0x98>
    10fb:	8b 82 14 00 00 00    	mov    eax,DWORD PTR [edx+0x14]
    1101:	85 c0                	test   eax,eax
    1103:	74 13                	je     1118 <__libc_start_main@plt+0x98>
    1105:	55                   	push   ebp
    1106:	89 e5                	mov    ebp,esp
    1108:	83 ec 14             	sub    esp,0x14
    110b:	51                   	push   ecx
    110c:	ff d0                	call   eax
    110e:	83 c4 10             	add    esp,0x10
    1111:	c9                   	leave  
    1112:	c3                   	ret    
    1113:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
    1117:	90                   	nop
    1118:	c3                   	ret    
    1119:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
    1120:	e8 a4 00 00 00       	call   11c9 <__libc_start_main@plt+0x149>
    1125:	81 c2 b3 2e 00 00    	add    edx,0x2eb3
    112b:	55                   	push   ebp
    112c:	89 e5                	mov    ebp,esp
    112e:	53                   	push   ebx
    112f:	8d 8a 30 00 00 00    	lea    ecx,[edx+0x30]
    1135:	8d 82 30 00 00 00    	lea    eax,[edx+0x30]
    113b:	83 ec 04             	sub    esp,0x4
    113e:	29 c8                	sub    eax,ecx
    1140:	89 c3                	mov    ebx,eax
    1142:	c1 e8 1f             	shr    eax,0x1f
    1145:	c1 fb 02             	sar    ebx,0x2
    1148:	01 d8                	add    eax,ebx
    114a:	d1 f8                	sar    eax,1
    114c:	74 14                	je     1162 <__libc_start_main@plt+0xe2>
    114e:	8b 92 24 00 00 00    	mov    edx,DWORD PTR [edx+0x24]
    1154:	85 d2                	test   edx,edx
    1156:	74 0a                	je     1162 <__libc_start_main@plt+0xe2>
    1158:	83 ec 08             	sub    esp,0x8
    115b:	50                   	push   eax
    115c:	51                   	push   ecx
    115d:	ff d2                	call   edx
    115f:	83 c4 10             	add    esp,0x10
    1162:	8b 5d fc             	mov    ebx,DWORD PTR [ebp-0x4]
    1165:	c9                   	leave  
    1166:	c3                   	ret    
    1167:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
    116e:	66 90                	xchg   ax,ax
    1170:	f3 0f 1e fb          	endbr32 
    1174:	55                   	push   ebp
    1175:	89 e5                	mov    ebp,esp
    1177:	53                   	push   ebx
    1178:	e8 53 ff ff ff       	call   10d0 <__libc_start_main@plt+0x50>
    117d:	81 c3 5b 2e 00 00    	add    ebx,0x2e5b
    1183:	83 ec 04             	sub    esp,0x4
    1186:	80 bb 30 00 00 00 00 	cmp    BYTE PTR [ebx+0x30],0x0
    118d:	75 27                	jne    11b6 <__libc_start_main@plt+0x136>
    118f:	8b 83 18 00 00 00    	mov    eax,DWORD PTR [ebx+0x18]
    1195:	85 c0                	test   eax,eax
    1197:	74 11                	je     11aa <__libc_start_main@plt+0x12a>
    1199:	83 ec 0c             	sub    esp,0xc
    119c:	ff b3 2c 00 00 00    	push   DWORD PTR [ebx+0x2c]
    11a2:	e8 b9 fe ff ff       	call   1060 <__cxa_finalize@plt>
    11a7:	83 c4 10             	add    esp,0x10
    11aa:	e8 31 ff ff ff       	call   10e0 <__libc_start_main@plt+0x60>
    11af:	c6 83 30 00 00 00 01 	mov    BYTE PTR [ebx+0x30],0x1
    11b6:	8b 5d fc             	mov    ebx,DWORD PTR [ebp-0x4]
    11b9:	c9                   	leave  
    11ba:	c3                   	ret    
    11bb:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
    11bf:	90                   	nop
    11c0:	f3 0f 1e fb          	endbr32 
    11c4:	e9 57 ff ff ff       	jmp    1120 <__libc_start_main@plt+0xa0>
    11c9:	8b 14 24             	mov    edx,DWORD PTR [esp]
    11cc:	c3                   	ret    
    11cd:	f3 0f 1e fb          	endbr32 
    11d1:	8d 4c 24 04          	lea    ecx,[esp+0x4]
    11d5:	83 e4 f0             	and    esp,0xfffffff0
    11d8:	ff 71 fc             	push   DWORD PTR [ecx-0x4]
    11db:	55                   	push   ebp
    11dc:	89 e5                	mov    ebp,esp
    11de:	53                   	push   ebx
    11df:	51                   	push   ecx
    11e0:	e8 28 00 00 00       	call   120d <__libc_start_main@plt+0x18d>
    11e5:	05 f3 2d 00 00       	add    eax,0x2df3
    11ea:	83 ec 0c             	sub    esp,0xc
    11ed:	8d 90 30 e0 ff ff    	lea    edx,[eax-0x1fd0]
    11f3:	52                   	push   edx
    11f4:	89 c3                	mov    ebx,eax
    11f6:	e8 75 fe ff ff       	call   1070 <puts@plt>
    11fb:	83 c4 10             	add    esp,0x10
    11fe:	b8 00 00 00 00       	mov    eax,0x0
    1203:	8d 65 f8             	lea    esp,[ebp-0x8]
    1206:	59                   	pop    ecx
    1207:	5b                   	pop    ebx
    1208:	5d                   	pop    ebp
    1209:	8d 61 fc             	lea    esp,[ecx-0x4]
    120c:	c3                   	ret    
    120d:	8b 04 24             	mov    eax,DWORD PTR [esp]
    1210:	c3                   	ret    
    1211:	66 90                	xchg   ax,ax
    1213:	66 90                	xchg   ax,ax
    1215:	66 90                	xchg   ax,ax
    1217:	66 90                	xchg   ax,ax
    1219:	66 90                	xchg   ax,ax
    121b:	66 90                	xchg   ax,ax
    121d:	66 90                	xchg   ax,ax
    121f:	90                   	nop
    1220:	f3 0f 1e fb          	endbr32 
    1224:	55                   	push   ebp
    1225:	e8 6b 00 00 00       	call   1295 <__libc_start_main@plt+0x215>
    122a:	81 c5 ae 2d 00 00    	add    ebp,0x2dae
    1230:	57                   	push   edi
    1231:	56                   	push   esi
    1232:	53                   	push   ebx
    1233:	83 ec 0c             	sub    esp,0xc
    1236:	89 eb                	mov    ebx,ebp
    1238:	8b 7c 24 28          	mov    edi,DWORD PTR [esp+0x28]
    123c:	e8 bf fd ff ff       	call   1000 <__cxa_finalize@plt-0x60>
    1241:	8d 9d 04 ff ff ff    	lea    ebx,[ebp-0xfc]
    1247:	8d 85 00 ff ff ff    	lea    eax,[ebp-0x100]
    124d:	29 c3                	sub    ebx,eax
    124f:	c1 fb 02             	sar    ebx,0x2
    1252:	74 29                	je     127d <__libc_start_main@plt+0x1fd>
    1254:	31 f6                	xor    esi,esi
    1256:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
    125d:	8d 76 00             	lea    esi,[esi+0x0]
    1260:	83 ec 04             	sub    esp,0x4
    1263:	57                   	push   edi
    1264:	ff 74 24 2c          	push   DWORD PTR [esp+0x2c]
    1268:	ff 74 24 2c          	push   DWORD PTR [esp+0x2c]
    126c:	ff 94 b5 00 ff ff ff 	call   DWORD PTR [ebp+esi*4-0x100]
    1273:	83 c6 01             	add    esi,0x1
    1276:	83 c4 10             	add    esp,0x10
    1279:	39 f3                	cmp    ebx,esi
    127b:	75 e3                	jne    1260 <__libc_start_main@plt+0x1e0>
    127d:	83 c4 0c             	add    esp,0xc
    1280:	5b                   	pop    ebx
    1281:	5e                   	pop    esi
    1282:	5f                   	pop    edi
    1283:	5d                   	pop    ebp
    1284:	c3                   	ret    
    1285:	8d b4 26 00 00 00 00 	lea    esi,[esi+eiz*1+0x0]
    128c:	8d 74 26 00          	lea    esi,[esi+eiz*1+0x0]
    1290:	f3 0f 1e fb          	endbr32 
    1294:	c3                   	ret    
    1295:	8b 2c 24             	mov    ebp,DWORD PTR [esp]
    1298:	c3                   	ret    

Disassembly of section .fini:

0000129c <.fini>:
    129c:	f3 0f 1e fb          	endbr32 
    12a0:	53                   	push   ebx
    12a1:	83 ec 08             	sub    esp,0x8
    12a4:	e8 27 fe ff ff       	call   10d0 <__libc_start_main@plt+0x50>
    12a9:	81 c3 2f 2d 00 00    	add    ebx,0x2d2f
    12af:	83 c4 08             	add    esp,0x8
    12b2:	5b                   	pop    ebx
    12b3:	c3                   	ret    

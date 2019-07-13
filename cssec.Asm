.586
.model flat, stdcall  
option casemap :none  
;include windows.inc
include windows.inc
include masm32.inc
include gdi32.inc
include ole32.inc
include user32.inc
include comctl32.inc
include kernel32.inc
include shell32.inc

includelib masm32.lib
includelib gdi32.lib
includelib ole32.lib
includelib oleaut32.lib
includelib user32.lib
includelib comctl32.lib
includelib kernel32.lib
includelib shell32.lib



CTEXT    MACRO y:VARARG
    LOCAL sym
    CONST segment
    ifidni <y>,<>            
        sym db 0        
    else            
        sym db y,0
    endif
    CONST ends
    exitm <offset sym>
ENDM 

     
.data  
count1      dd 0
count2      dd 0
count3      dd 0
flag        dd 0

        
.data?
hInstance   dd ?   
ProcessId   dd ?
ThreadId    dd ?
ThreadId2   dd ?
lpbaseaddr  dd ?
hProcess    dd ?
hThread     dd ?
hDlg        dd ?
FilePath    dd ?
ModBase     dd ?
hDll        dd ?

.code    
include cssec.inc     
Main proc hinstdll:DWORD , reason:DWORD , reserved1:DWORD        
        pushad                                   
        .if reason == DLL_PROCESS_ATTACH

                                          
        .elseif reason == DLL_PROCESS_DETACH

              
        .elseif reason == DLL_THREAD_ATTACH
           
        .endif

        popad
        mov  eax,TRUE
        ret     
Main    endp  

FindPort proc agr:dword,OutPath:LPCSTR
        lea eax,offset DogPath
        mov OutPath,eax
        xor eax,eax
        ret
FindPort endp
ReadKeyFormEpm proc OutAuthCode:LPSTR, szAddr:dword, HKey:LPCSTR, Lkey:dword, KeyPath:LPCSTR
        lea edx,offset DogPath
        mov KeyPath,edx
        mov edi,00007530h
        mov Lkey,edi
        mov ecx,0fffffffh
        mov HKey,ecx
        mov eax, offset Data1
        mov OutAuthCode,eax
        xor eax,eax
        ret
ReadKeyFormEpm endp
EdccBin proc OutAuthCode:LPCSTR, InByte:dword, in_len:dword, OutErrCode:dword, KeyPath:LPCSTR 
        mov ecx,count1
        .if ecx==0
        	lea edx,offset DogPath
                mov KeyPath,edx
                lea eax,offset Data1
                mov OutAuthCode,eax
                mov ecx,0000001Ah
                mov in_len,ecx
                lea edx,offset InByte1
                mov InByte,edx
        .elseif ecx==1
        	lea edx,offset DogPath
                mov KeyPath,edx
                lea eax,offset Data1
                mov OutAuthCode,eax
                mov ecx,00000312h
                mov in_len,ecx
                lea edx,offset InByte2
                mov InByte,edx
        .elseif ecx==2
        	lea edx,offset DogPath
                mov KeyPath,edx
                lea eax,offset Data1
                mov OutAuthCode,eax
                mov ecx,0000033Ah
                mov in_len,ecx
                lea edx,offset InByte3
                mov InByte,edx
        .endif
        inc count1
        mov eax,1
        ret
EdccBin endp
CalPub proc C InByte, len, agr3, agr4, agr5, agr6, agr7, agr8, agr9, agr10, agr11, agr12, agr13, agr14, agr15, agr16, agr17, agr18, agr19, agr20, agr21, agr22, agr23, agr24, agr25, agr26, KeyPath:LPCSTR, over_count
        mov ecx,count2
        .if ecx==0
        	lea edx,offset DogPath
                mov KeyPath,edx
                mov agr26,0
                mov agr25,0
                mov agr24,0
                mov agr23,0
                mov agr22,0
                mov agr21,0
                mov agr20,0
                mov agr19,0
                
                mov agr19,0
                mov agr18,0
                mov agr17,0
                mov agr16,0
                mov agr15,0
                mov agr14,0
                mov agr13,0
                mov agr12,0
                mov agr11,0
                
                mov agr10,0
                mov agr9,0
                mov agr8,0
                mov agr7,0
                mov agr6,0
                mov agr5,0
                mov agr4,0
                mov agr3,0
                mov ecx,00004E20h
                mov over_count,ecx
                mov ecx,1Ah
                mov len,ecx
                lea edx,offset InByte1
                mov InByte,edx
        .elseif ecx==1
        	lea edx,offset DogPath
                mov KeyPath,edx
                mov agr26,0
                mov agr25,0
                mov agr24,0
                mov agr23,0
                mov agr22,0
                mov agr21,0
                mov agr20,0
                mov agr19,0
                
                mov agr19,0
                mov agr18,0
                mov agr17,0
                mov agr16,0
                mov agr15,0
                mov agr14,0
                mov agr13,0
                mov agr12,0
                mov agr11,0
                
                mov agr10,0
                mov agr9,0
                mov agr8,0
                mov agr7,0
                mov agr6,0
                mov agr5,0
                mov agr4,0
                mov agr3,0
                mov ecx,01312D00h
                mov over_count,ecx
                mov ecx,00000312h
                mov len,ecx
                lea edx,offset InByte2
                mov InByte,edx
        .elseif ecx==2
        	lea edx,offset DogPath
                mov KeyPath,edx
                mov agr26,0
                mov agr25,0
                mov agr24,0
                mov agr23,0
                mov agr22,0
                mov agr21,0
                mov agr20,0
                mov agr19,0
                
                mov agr19,0
                mov agr18,0
                mov agr17,0
                mov agr16,0
                mov agr15,0
                mov agr14,0
                mov agr13,0
                mov agr12,0
                mov agr11,0
                
                mov agr10,0
                mov agr9,0
                mov agr8,0
                mov agr7,0
                mov agr6,0
                mov agr5,0
                mov agr4,0
                mov agr3,0
                mov ecx,01312D00h
                mov over_count,ecx
                mov ecx,0000033Ah
                mov len,ecx
                lea edx,offset InByte3
                mov InByte,edx
        .elseif ecx==3
        	lea edx,offset DogPath
                mov KeyPath,edx
                mov agr26,0
                mov agr25,0
                mov agr24,0
                mov agr23,0
                mov agr22,0
                mov agr21,0
                mov agr20,0
                mov agr19,0
                
                mov agr19,0
                mov agr18,0
                mov agr17,0
                mov agr16,0
                mov agr15,0
                mov agr14,0
                mov agr13,0
                mov agr12,0
                mov agr11,0
                
                mov agr10,0
                mov agr9,0
                mov agr8,0
                mov agr7,0
                mov agr6,0
                mov agr5,0
                mov agr4,0
                mov agr3,0
                mov ecx,01312D00h
                mov over_count,ecx
                mov ecx,0000033Ah
                mov len,ecx
                lea edx,offset InByte3
                mov InByte,edx
        .elseif ecx==4
        	
        .elseif ecx==5				
        .endif
        inc count2
        xor eax,eax
        ret
CalPub endp
GetRunTimer proc OutYear:LPSTR, OutMonth:LPSTR, OutDay:LPSTR, OutHour:LPSTR, OutMinuts:LPSTR, OutSecond:LPSTR, InPath:dword ;加密锁所在的设备路径

        xor eax,eax
        ret
GetRunTimer endp
YtReadLong proc OutData:dword, address:dword, HKey:LPCSTR, Lkey:dword, agr5:dword, InPath:LPCSTR
        mov ecx,count3
        .if ecx==0
               lea edx,offset DogPath
               mov InPath,edx
               mov Lkey,0
               mov HKey,0
               mov OutData,0
               mov address,0
        .elseif ecx==1
               lea edx,offset DogPath
               mov InPath,edx
               mov Lkey,0
               mov HKey,0
               mov OutData,0
               mov address,0
        .endif
        inc count3
        xor eax,eax
        ret
YtReadLong endp

END  Main





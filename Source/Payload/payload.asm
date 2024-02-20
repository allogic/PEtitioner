extern printf : proc

.data

	msg db "Hello Asm Payload"

.code

KduAsmPayload proc export
	sub rsp, 32
	lea rcx, msg
	call printf
	add rsp, 32
	ret
KduAsmPayload endp

end
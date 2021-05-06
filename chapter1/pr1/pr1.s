	.file	"pr1.c"
	.intel_syntax noprefix
	.section	.rodata
.LC0:
	.string	"/bin/sh"
	.text
	.globl	getFlag
	.type	getFlag, @function
getFlag:
.LFB2:
	.cfi_startproc
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
	.cfi_def_cfa_register 6
	mov	edi, OFFSET FLAT:.LC0
	call	system
	nop
	pop	rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2:
	.size	getFlag, .-getFlag
	.globl	replaceTo
	.type	replaceTo, @function
replaceTo:
.LFB3:
	.cfi_startproc
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
	.cfi_def_cfa_register 6
	mov	QWORD PTR [rbp-8], rdi
	mov	rax, QWORD PTR [rbp-8]
	mov	DWORD PTR [rax], 20
	nop
	pop	rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3:
	.size	replaceTo, .-replaceTo
	.section	.rodata
.LC1:
	.string	"[%d]\n"
	.text
	.globl	main
	.type	main, @function
main:
.LFB4:
	.cfi_startproc
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
	.cfi_def_cfa_register 6
	sub	rsp, 32
	mov	rax, QWORD PTR fs:40
	mov	QWORD PTR [rbp-8], rax
	xor	eax, eax
	mov	edi, 4
	call	malloc
	mov	QWORD PTR [rbp-16], rax
	mov	DWORD PTR [rbp-20], 10
	mov	rax, QWORD PTR [rbp-16]
	mov	edx, 4
	mov	esi, 0
	mov	rdi, rax
	call	memset
	lea	rax, [rbp-20]
	mov	QWORD PTR [rbp-16], rax
	mov	eax, DWORD PTR [rbp-20]
	mov	esi, eax
	mov	edi, OFFSET FLAT:.LC1
	mov	eax, 0
	call	printf
	mov	rax, QWORD PTR [rbp-16]
	mov	rdi, rax
	call	replaceTo
	mov	eax, DWORD PTR [rbp-20]
	mov	esi, eax
	mov	edi, OFFSET FLAT:.LC1
	mov	eax, 0
	call	printf
	mov	eax, 0
	call	getFlag
	nop
	mov	rax, QWORD PTR [rbp-8]
	xor	rax, QWORD PTR fs:40
	je	.L4
	call	__stack_chk_fail
.L4:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE4:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.5) 5.4.0 20160609"
	.section	.note.GNU-stack,"",@progbits

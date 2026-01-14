.global setjmp
.global _setjmp
.type setjmp, @function
.type _setjmp, @function

setjmp:
_setjmp:
    movl 4(%esp), %eax
    movl %ebx, (%eax)
    movl %esi, 4(%eax)
    movl %edi, 8(%eax)
    movl %ebp, 12(%eax)
    leal 4(%esp), %ecx
    movl %ecx, 16(%eax)
    movl (%esp), %ecx
    movl %ecx, 20(%eax)
    xorl %eax, %eax
    ret

.global longjmp
.global _longjmp
.type longjmp, @function
.type _longjmp, @function

longjmp:
_longjmp:
    movl 4(%esp), %edx
    movl 8(%esp), %eax
    cmpl $1, %eax
    adcl $0, %eax
    movl (%edx), %ebx
    movl 4(%edx), %esi
    movl 8(%edx), %edi
    movl 12(%edx), %ebp
    movl 16(%edx), %esp
    jmp *20(%edx)

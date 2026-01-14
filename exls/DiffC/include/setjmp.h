#pragma once

typedef unsigned long jmp_buf[6];

int setjmp(jmp_buf env);
int _setjmp(jmp_buf env);
void longjmp(jmp_buf env, int val);
void _longjmp(jmp_buf env, int val);

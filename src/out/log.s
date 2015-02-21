.section	".text"
.section	".rodata"
	.align 8
.LLC0:
	.asciz	""
.section	".data"
.stabs "extra_string:S(7,8)",38,0,44,extra_string
	.align 4
	.type	 extra_string,#object
	.size	 extra_string,4
extra_string:
	.uaword	.LLC0
.section	".rodata"
	.align 8
.LLC1:
	.asciz	"%s %s:%d => %s:%d (%s)"
	.align 8
.LLC2:
	.asciz	"%s %s => %s (%s)"
	.align 8
.LLC3:
	.asciz	"%s %02x:%02x:%02x:%02x:%02x:%02x => %02x:%02x:%02x:%02x:%02x:%02x (%s)"
.section	".text"
	.align 4
.stabs "action:f(0,19)",36,0,52,action
.stabs "dg:p(0,20)=*(20,1)",160,0,51,68
.stabs "cf:p(25,6)",160,0,51,72
.stabs "len:p(1,1)",160,0,51,76
.stabs "tid:p(0,1)",160,0,51,80
	.type	 action,#function
	.proc	020
action:
.stabn 68,0,52,.LLM1-action
.LLM1:
	!#PROLOGUE# 0
	save	%sp, -168, %sp
	!#PROLOGUE# 1
	st	%i0, [%fp+68]
	st	%i1, [%fp+72]
	st	%i2, [%fp+76]
	st	%i3, [%fp+80]
.stabn 68,0,53,.LLM2-action
.LLM2:
.LLBB2:
	ld	[%fp+68], %o0
	add	%o0, 14, %o1
	st	%o1, [%fp-20]
.stabn 68,0,54,.LLM3-action
.LLM3:
	ld	[%fp-20], %o0
	ldub	[%o0], %o1
	and	%o1, 15, %o0
	and	%o0, 0xff, %o1
	sll	%o1, 2, %o0
	add	%o0, 14, %o1
	ld	[%fp+68], %o0
	add	%o0, %o1, %o1
	st	%o1, [%fp-24]
.stabn 68,0,55,.LLM4-action
.LLM4:
	ld	[%fp+72], %o0
	ld	[%o0+144], %o1
	st	%o1, [%fp-28]
.stabn 68,0,56,.LLM5-action
.LLM5:
	ld	[%fp-28], %o0
	cmp	%o0, 0
	bne	.LL3
	nop
.stabn 68,0,57,.LLM6-action
.LLM6:
	sethi	%hi(.LLC0), %o1
	or	%o1, %lo(.LLC0), %o0
	st	%o0, [%fp-28]
.LL3:
.stabn 68,0,62,.LLM7-action
.LLM7:
	sethi	%hi(action_done), %o1
	or	%o1, %lo(action_done), %o0
	mov	1, %o1
	st	%o1, [%o0]
.stabn 68,0,65,.LLM8-action
.LLM8:
	ld	[%fp+68], %o0
	lduh	[%o0+12], %o1
	sll	%o1, 16, %o2
	srl	%o2, 16, %o0
	cmp	%o0, 2048
	bne	.LL4
	nop
	ld	[%fp-20], %o0
	ldub	[%o0], %o1
	and	%o1, 240, %o0
	and	%o0, 0xff, %o1
	srl	%o1, 4, %o0
	and	%o0, 0xff, %o1
	cmp	%o1, 4
	bne	.LL4
	nop
.stabn 68,0,66,.LLM9-action
.LLM9:
	ld	[%fp-20], %o0
	ldub	[%o0+9], %o1
	and	%o1, 0xff, %o0
	cmp	%o0, 6
	be	.LL6
	nop
	ld	[%fp-20], %o0
	ldub	[%o0+9], %o1
	and	%o1, 0xff, %o0
	cmp	%o0, 17
	be	.LL6
	nop
	b	.LL5
	 nop
.LL6:
.stabn 68,0,68,.LLM10-action
.LLM10:
.LLBB3:
	ld	[%fp-20], %o1
	ld	[%o1+12], %o0
	call	ip2string, 0
	 nop
	mov	%o0, %l0
	ld	[%fp-24], %o0
	lduh	[%o0], %o1
	sll	%o1, 16, %o0
	srl	%o0, 16, %o1
	mov	%o1, %o0
	call	ntohs, 0
	 nop
	mov	%o0, %l1
	ld	[%fp-20], %o1
	ld	[%o1+16], %o0
	call	ip2string, 0
	 nop
	mov	%o0, %l2
	ld	[%fp-24], %o0
	lduh	[%o0+2], %o1
	sll	%o1, 16, %o0
	srl	%o0, 16, %o1
	mov	%o1, %o0
	call	ntohs, 0
	 nop
	mov	%o0, %o5
	sethi	%hi(extra_string), %o1
	or	%o1, %lo(extra_string), %o0
	ld	[%o0], %o1
	st	%o1, [%sp+92]
	sethi	%hi(.LLC1), %o1
	or	%o1, %lo(.LLC1), %o0
	ld	[%fp-28], %o1
	mov	%l0, %o2
	mov	%l1, %o3
	mov	%l2, %o4
	call	netl_log, 0
	 nop
.stabn 68,0,70,.LLM11-action
.LLM11:
.LLBE3:
	b	.LL7
	 nop
.LL5:
.stabn 68,0,72,.LLM12-action
.LLM12:
	ld	[%fp-20], %o1
	ld	[%o1+12], %o0
	call	ip2string, 0
	 nop
	mov	%o0, %l0
	ld	[%fp-20], %o1
	ld	[%o1+16], %o0
	call	ip2string, 0
	 nop
	mov	%o0, %o3
	sethi	%hi(extra_string), %o0
	or	%o0, %lo(extra_string), %o4
	sethi	%hi(.LLC2), %o1
	or	%o1, %lo(.LLC2), %o0
	ld	[%fp-28], %o1
	mov	%l0, %o2
	ld	[%o4], %o4
	call	netl_log, 0
	 nop
.LL7:
.stabn 68,0,75,.LLM13-action
.LLM13:
	b	.LL8
	 nop
.LL4:
.stabn 68,0,77,.LLM14-action
.LLM14:
	mov	6, %o0
	ld	[%fp+68], %o1
	add	%o0, %o1, %o0
	ldub	[%o0], %o1
	and	%o1, 0xff, %o2
	mov	7, %o0
	ld	[%fp+68], %o1
	add	%o0, %o1, %o0
	ldub	[%o0], %o1
	and	%o1, 0xff, %o3
	mov	8, %o0
	ld	[%fp+68], %o1
	add	%o0, %o1, %o0
	ldub	[%o0], %o1
	and	%o1, 0xff, %o4
	mov	9, %o0
	ld	[%fp+68], %o1
	add	%o0, %o1, %o0
	ldub	[%o0], %o1
	and	%o1, 0xff, %o5
	mov	10, %o0
	ld	[%fp+68], %o1
	add	%o0, %o1, %o0
	ldub	[%o0], %o1
	and	%o1, 0xff, %o0
	st	%o0, [%sp+92]
	mov	11, %o0
	ld	[%fp+68], %o1
	add	%o0, %o1, %o0
	ldub	[%o0], %o1
	and	%o1, 0xff, %o0
	st	%o0, [%sp+96]
	ld	[%fp+68], %o0
	ldub	[%o0], %o1
	and	%o1, 0xff, %o0
	st	%o0, [%sp+100]
	mov	1, %o0
	ld	[%fp+68], %o1
	add	%o0, %o1, %o0
	ldub	[%o0], %o1
	and	%o1, 0xff, %o0
	st	%o0, [%sp+104]
	mov	2, %o0
	ld	[%fp+68], %o1
	add	%o0, %o1, %o0
	ldub	[%o0], %o1
	and	%o1, 0xff, %o0
	st	%o0, [%sp+108]
	mov	3, %o0
	ld	[%fp+68], %o1
	add	%o0, %o1, %o0
	ldub	[%o0], %o1
	and	%o1, 0xff, %o0
	st	%o0, [%sp+112]
	mov	4, %o0
	ld	[%fp+68], %o1
	add	%o0, %o1, %o0
	ldub	[%o0], %o1
	and	%o1, 0xff, %o0
	st	%o0, [%sp+116]
	mov	5, %o0
	ld	[%fp+68], %o1
	add	%o0, %o1, %o0
	ldub	[%o0], %o1
	and	%o1, 0xff, %o0
	st	%o0, [%sp+120]
	sethi	%hi(extra_string), %o1
	or	%o1, %lo(extra_string), %o0
	ld	[%o0], %o1
	st	%o1, [%sp+124]
	sethi	%hi(.LLC3), %o1
	or	%o1, %lo(.LLC3), %o0
	ld	[%fp-28], %o1
	call	netl_log, 0
	 nop
.LL8:
.stabn 68,0,82,.LLM15-action
.LLM15:
.LLBE2:
.stabn 68,0,82,.LLM16-action
.LLM16:
.LL2:
	ret
	restore
.LLfe1:
	.size	 action,.LLfe1-action
.stabs "ip:(0,21)=*(22,3)",128,0,53,-20
.stabs "t:(0,22)=*(22,26)",128,0,54,-24
.stabs "logname:(7,8)",128,0,55,-28
.stabn 192,0,0,.LLBB2-action
.stabn 192,0,0,.LLBB3-action
.stabn 224,0,0,.LLBE3-action
.stabn 224,0,0,.LLBE2-action
.LLscope0:
.stabs "",36,0,0,.LLscope0-action
.section	".rodata"
	.align 8
.LLC4:
	.asciz	"out/log.so"
	.align 8
.LLC5:
	.asciz	"action_done"
	.align 8
.LLC6:
	.asciz	"action"
	.align 8
.LLC7:
	.asciz	"extra_string"
.section	".text"
	.align 4
.stabs "out_log_register_symbols:F(0,19)",36,0,87,out_log_register_symbols
	.global out_log_register_symbols
	.type	 out_log_register_symbols,#function
	.proc	020
out_log_register_symbols:
.stabn 68,0,87,.LLM17-out_log_register_symbols
.LLM17:
	!#PROLOGUE# 0
	save	%sp, -112, %sp
	!#PROLOGUE# 1
.stabn 68,0,88,.LLM18-out_log_register_symbols
.LLM18:
.LLBB4:
	sethi	%hi(.LLC4), %o1
	or	%o1, %lo(.LLC4), %o0
	sethi	%hi(.LLC5), %o2
	or	%o2, %lo(.LLC5), %o1
	sethi	%hi(action_done), %o3
	or	%o3, %lo(action_done), %o2
	call	register_symbol, 0
	 nop
.stabn 68,0,89,.LLM19-out_log_register_symbols
.LLM19:
	sethi	%hi(.LLC4), %o1
	or	%o1, %lo(.LLC4), %o0
	sethi	%hi(.LLC6), %o2
	or	%o2, %lo(.LLC6), %o1
	sethi	%hi(action), %o3
	or	%o3, %lo(action), %o2
	call	register_symbol, 0
	 nop
.stabn 68,0,90,.LLM20-out_log_register_symbols
.LLM20:
	sethi	%hi(.LLC4), %o1
	or	%o1, %lo(.LLC4), %o0
	sethi	%hi(.LLC7), %o2
	or	%o2, %lo(.LLC7), %o1
	sethi	%hi(extra_string), %o3
	or	%o3, %lo(extra_string), %o2
	call	register_symbol, 0
	 nop
.stabn 68,0,91,.LLM21-out_log_register_symbols
.LLM21:
.LLBE4:
.stabn 68,0,91,.LLM22-out_log_register_symbols
.LLM22:
.LL9:
	ret
	restore
.LLfe2:
	.size	 out_log_register_symbols,.LLfe2-out_log_register_symbols
.stabn 192,0,0,.LLBB4-out_log_register_symbols
.stabn 224,0,0,.LLBE4-out_log_register_symbols
.LLscope1:
.stabs "",36,0,0,.LLscope1-out_log_register_symbols
.stabs "netl_death_message:G(7,8)",32,0,31,0
	.common	netl_death_message,4,4
.stabs "action_done:S(0,1)",40,0,42,action_done
	.local	action_done
	.common	action_done,4,4
	.text
	.stabs "",100,0,0,Letext
Letext:
	.ident	"GCC: (GNU) 2.95 19990728 (release)"

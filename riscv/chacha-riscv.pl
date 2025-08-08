#!/usr/bin/perl
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use with OpenSSL.
# ====================================================================
#
# ChaCha20 for RISC-V.
#
# March 2019.
#
# This is transliteration of MIPS module [without big-endian option].
#
# 14.1 cycles per byte on U74 for aligned input, ~70% faster than
# compiler-generated code. Misaligned input is processed in 16.4 cpb.
# C910 processes one byte in 13.7 cycles. JH7110 (U74+zbb) - in 10.3.
# Spacemit X60 - in 8.6.
#
# October 2023.
#
# Add a "teaser" vector implementation. It's a "teaser," because one
# can improve it further for longer inputs. But it makes no sense to
# invest time prior vector-capable hardware appears, so that one can
# make suitable choices. Spacemit X60 processes one byte in 10.0
# cycles. Next step is to interleave 3 blocks, but it won't improve
# performance by 3x on X60. Hence below "vertical" implementation is
# an adequate option for it. It remains to be seen how it looks on
# other processors to draw the final conclusion...
#
# June 2024.
#
# Add CHERI support.
#
# July 2025.
#
# Add "vertical" vector implementation. It dynamically adapts to vlen
# in attempt to maximize resource utilization. Spacemit X60 processes
# one byte in 6.0 cycles.
#
######################################################################
#
($zero,$ra,$sp,$gp,$tp) = map("x$_",(0..4));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("x$_",(10..17));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8,$s9,$s10,$s11)=map("x$_",(8,9,18..27));
($t0,$t1,$t2,$t3,$t4,$t5,$t6)=map("x$_",(5..7, 28..31));
#
######################################################################

$flavour = shift;	# "cheri" is the only meaningful option

my @x = map("x$_",(16..31));
my @y = map("x$_",(5..9,13,14));
my $at = @y[-1];
my ($out, $inp, $len, $key, $counter) = ($a0,$a1,$a2,$a3,$a4);

sub ROUND {
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));

$code.=<<___;
	add		@x[$a0],@x[$a0],@x[$b0]		# Q0
	 add		@x[$a1],@x[$a1],@x[$b1]		# Q1
	  add		@x[$a2],@x[$a2],@x[$b2]		# Q2
	   add		@x[$a3],@x[$a3],@x[$b3]		# Q3
	xor		@x[$d0],@x[$d0],@x[$a0]
	 xor		@x[$d1],@x[$d1],@x[$a1]
	  xor		@x[$d2],@x[$d2],@x[$a2]
	   xor		@x[$d3],@x[$d3],@x[$a3]
#ifdef	__riscv_zbb
	rorw		@x[$d0],@x[$d0],16
	 rorw		@x[$d1],@x[$d1],16
	  rorw		@x[$d2],@x[$d2],16
	   rorw		@x[$d3],@x[$d3],16
#else
	srlw		@y[0],@x[$d0],16
	 srlw		@y[1],@x[$d1],16
	  srlw		@y[2],@x[$d2],16
	   srlw		@y[3],@x[$d3],16
	sll		@x[$d0],@x[$d0],16
	 sll		@x[$d1],@x[$d1],16
	  sll		@x[$d2],@x[$d2],16
	   sll		@x[$d3],@x[$d3],16
	or		@x[$d0],@x[$d0],@y[0]
	 or		@x[$d1],@x[$d1],@y[1]
	  or		@x[$d2],@x[$d2],@y[2]
	   or		@x[$d3],@x[$d3],@y[3]
#endif

	add		@x[$c0],@x[$c0],@x[$d0]
	 add		@x[$c1],@x[$c1],@x[$d1]
	  add		@x[$c2],@x[$c2],@x[$d2]
	   add		@x[$c3],@x[$c3],@x[$d3]
	xor		@x[$b0],@x[$b0],@x[$c0]
	 xor		@x[$b1],@x[$b1],@x[$c1]
	  xor		@x[$b2],@x[$b2],@x[$c2]
	   xor		@x[$b3],@x[$b3],@x[$c3]
#ifdef	__riscv_zbb
	rorw		@x[$b0],@x[$b0],20
	 rorw		@x[$b1],@x[$b1],20
	  rorw		@x[$b2],@x[$b2],20
	   rorw		@x[$b3],@x[$b3],20
#else
	srlw		@y[0],@x[$b0],20
	 srlw		@y[1],@x[$b1],20
	  srlw		@y[2],@x[$b2],20
	   srlw		@y[3],@x[$b3],20
	sll		@x[$b0],@x[$b0],12
	 sll		@x[$b1],@x[$b1],12
	  sll		@x[$b2],@x[$b2],12
	   sll		@x[$b3],@x[$b3],12
	or		@x[$b0],@x[$b0],@y[0]
	 or		@x[$b1],@x[$b1],@y[1]
	  or		@x[$b2],@x[$b2],@y[2]
	   or		@x[$b3],@x[$b3],@y[3]
#endif

	add		@x[$a0],@x[$a0],@x[$b0]
	 add		@x[$a1],@x[$a1],@x[$b1]
	  add		@x[$a2],@x[$a2],@x[$b2]
	   add		@x[$a3],@x[$a3],@x[$b3]
	xor		@x[$d0],@x[$d0],@x[$a0]
	 xor		@x[$d1],@x[$d1],@x[$a1]
	  xor		@x[$d2],@x[$d2],@x[$a2]
	   xor		@x[$d3],@x[$d3],@x[$a3]
#ifdef	__riscv_zbb
	rorw		@x[$d0],@x[$d0],24
	 rorw		@x[$d1],@x[$d1],24
	  rorw		@x[$d2],@x[$d2],24
	   rorw		@x[$d3],@x[$d3],24
#else
	srlw		@y[0],@x[$d0],24
	 srlw		@y[1],@x[$d1],24
	  srlw		@y[2],@x[$d2],24
	   srlw		@y[3],@x[$d3],24
	sll		@x[$d0],@x[$d0],8
	 sll		@x[$d1],@x[$d1],8
	  sll		@x[$d2],@x[$d2],8
	   sll		@x[$d3],@x[$d3],8
	or		@x[$d0],@x[$d0],@y[0]
	 or		@x[$d1],@x[$d1],@y[1]
	  or		@x[$d2],@x[$d2],@y[2]
	   or		@x[$d3],@x[$d3],@y[3]
#endif

	add		@x[$c0],@x[$c0],@x[$d0]
	 add		@x[$c1],@x[$c1],@x[$d1]
	  add		@x[$c2],@x[$c2],@x[$d2]
	   add		@x[$c3],@x[$c3],@x[$d3]
	xor		@x[$b0],@x[$b0],@x[$c0]
	 xor		@x[$b1],@x[$b1],@x[$c1]
	  xor		@x[$b2],@x[$b2],@x[$c2]
	   xor		@x[$b3],@x[$b3],@x[$c3]
#ifdef	__riscv_zbb
	rorw		@x[$b0],@x[$b0],25
	 rorw		@x[$b1],@x[$b1],25
	  rorw		@x[$b2],@x[$b2],25
	   rorw		@x[$b3],@x[$b3],25
#else
	srlw		@y[0],@x[$b0],25
	 srlw		@y[1],@x[$b1],25
	  srlw		@y[2],@x[$b2],25
	   srlw		@y[3],@x[$b3],25
	sll		@x[$b0],@x[$b0],7
	 sll		@x[$b1],@x[$b1],7
	  sll		@x[$b2],@x[$b2],7
	   sll		@x[$b3],@x[$b3],7
	or		@x[$b0],@x[$b0],@y[0]
	 or		@x[$b1],@x[$b1],@y[1]
	  or		@x[$b2],@x[$b2],@y[2]
	   or		@x[$b3],@x[$b3],@y[3]
#endif
___
}

$code.=<<___;
#if __riscv_xlen == 32
# if __SIZEOF_POINTER__ == 8
#  define PUSH	csc
#  define POP	clc
# else
#  define PUSH	sw
#  define POP	lw
# endif
# define srlw	srl
# define rorw	ror
#elif __riscv_xlen == 64
# if __SIZEOF_POINTER__ == 16
#  define PUSH	csc
#  define POP	clc
# else
#  define PUSH	sd
#  define POP	ld
# endif
#else
# error "unsupported __riscv_xlen"
#endif
#define FRAMESIZE		(64+16*__SIZEOF_POINTER__)

#if defined(__riscv_zbkb) && !defined(__riscv_zbb)
# define __riscv_zbb __riscv_zbkb
#endif

.text
.option	pic

.type	__ChaCha,\@function
.align	2
__ChaCha:
	lw		@x[0], 4*0($sp)
	lw		@x[1], 4*1($sp)
	lw		@x[2], 4*2($sp)
	lw		@x[3], 4*3($sp)
	lw		@x[4], 4*4($sp)
	lw		@x[5], 4*5($sp)
	lw		@x[6], 4*6($sp)
	lw		@x[7], 4*7($sp)
	lw		@x[8], 4*8($sp)
	lw		@x[9], 4*9($sp)
	lw		@x[10],4*10($sp)
	lw		@x[11],4*11($sp)
	mv		@x[12],$a5
	lw		@x[13],4*13($sp)
	lw		@x[14],4*14($sp)
	lw		@x[15],4*15($sp)
.Loop:
	addi		$at,$at,-1
___
	&ROUND(0, 4, 8, 12);
	&ROUND(0, 5, 10, 15);
$code.=<<___;
	bnez		$at,.Loop

	lw		@y[0], 4*0($sp)
	lw		@y[1], 4*1($sp)
	lw		@y[2], 4*2($sp)
	lw		@y[3], 4*3($sp)
	add		@x[0],@x[0],@y[0]
	lw		@y[0],4*4($sp)
	add		@x[1],@x[1],@y[1]
	lw		@y[1],4*5($sp)
	add		@x[2],@x[2],@y[2]
	lw		@y[2],4*6($sp)
	add		@x[3],@x[3],@y[3]
	lw		@y[3],4*7($sp)
	add		@x[4],@x[4],@y[0]
	lw		@y[0],4*8($sp)
	add		@x[5],@x[5],@y[1]
	lw		@y[1], 4*9($sp)
	add		@x[6],@x[6],@y[2]
	lw		@y[2],4*10($sp)
	add		@x[7],@x[7],@y[3]
	lw		@y[3],4*11($sp)
	add		@x[8],@x[8],@y[0]
	#lw		@y[0],4*12($sp)
	add		@x[9],@x[9],@y[1]
	lw		@y[1],4*13($sp)
	add		@x[10],@x[10],@y[2]
	lw		@y[2],4*14($sp)
	add		@x[11],@x[11],@y[3]
	lw		@y[3],4*15($sp)
	add		@x[12],@x[12],$a5
	add		@x[13],@x[13],@y[1]
	add		@x[14],@x[14],@y[2]
	add		@x[15],@x[15],@y[3]
	ret
.size	__ChaCha,.-__ChaCha

.globl	ChaCha20_ctr32
.type	ChaCha20_ctr32,\@function
.align	2
ChaCha20_ctr32:
#ifdef	__riscv_zicfilp
	lpad		0
#endif
	caddi		$sp,$sp,-FRAMESIZE
	PUSH		$ra, (FRAMESIZE-1*__SIZEOF_POINTER__)($sp)
	PUSH		$s0, (FRAMESIZE-2*__SIZEOF_POINTER__)($sp)
.Lscalar_shortcut:
	PUSH		$s1, (FRAMESIZE-3*__SIZEOF_POINTER__)($sp)
	PUSH		$s2, (FRAMESIZE-4*__SIZEOF_POINTER__)($sp)
	PUSH		$s3, (FRAMESIZE-5*__SIZEOF_POINTER__)($sp)
	PUSH		$s4, (FRAMESIZE-6*__SIZEOF_POINTER__)($sp)
	PUSH		$s5, (FRAMESIZE-7*__SIZEOF_POINTER__)($sp)
	PUSH		$s6, (FRAMESIZE-8*__SIZEOF_POINTER__)($sp)
	PUSH		$s7, (FRAMESIZE-9*__SIZEOF_POINTER__)($sp)
	PUSH		$s8, (FRAMESIZE-10*__SIZEOF_POINTER__)($sp)
	PUSH		$s9, (FRAMESIZE-11*__SIZEOF_POINTER__)($sp)
	PUSH		$s10,(FRAMESIZE-12*__SIZEOF_POINTER__)($sp)
	PUSH		$s11,(FRAMESIZE-13*__SIZEOF_POINTER__)($sp)

	lui		@x[0],0x61707+1		# compose sigma
	lui		@x[1],0x33206
	lui		@x[2],0x79622+1
	lui		@x[3],0x6b206
	addi		@x[0],@x[0],-0x79b
	addi		@x[1],@x[1],0x46e
	addi		@x[2],@x[2],-0x2ce
	addi		@x[3],@x[3],0x574

	lw		@x[4], 4*0($key)
	lw		@x[5], 4*1($key)
	lw		@x[6], 4*2($key)
	lw		@x[7], 4*3($key)
	lw		@x[8], 4*4($key)
	lw		@x[9], 4*5($key)
	lw		@x[10],4*6($key)
	lw		@x[11],4*7($key)

	lw		@x[12],4*0($counter)
	lw		@x[13],4*1($counter)
	lw		@x[14],4*2($counter)
	lw		@x[15],4*3($counter)

	sw		@x[0], 4*0($sp)
	sw		@x[1], 4*1($sp)
	sw		@x[2], 4*2($sp)
	sw		@x[3], 4*3($sp)
	sw		@x[4], 4*4($sp)
	sw		@x[5], 4*5($sp)
	sw		@x[6], 4*6($sp)
	sw		@x[7], 4*7($sp)
	sw		@x[8], 4*8($sp)
	sw		@x[9], 4*9($sp)
	sw		@x[10],4*10($sp)
	sw		@x[11],4*11($sp)
	mv		$a5,@x[12]
	sw		@x[13],4*13($sp)
	sw		@x[14],4*14($sp)
	sw		@x[15],4*15($sp)

	li		$at,10
	jal		.Loop

	sltiu		$at,$len,64
	or		$ra,$inp,$out
	andi		$ra,$ra,3		# both are aligned?
	bnez		$at,.Ltail

#ifndef	__riscv_misaligned_fast
	beqz		$ra,.Loop_aligned

.Loop_misaligned:
	lb		@y[0],0($inp)
	lb		@y[1],1($inp)
	srl		@y[4],@x[0],8
	lb		@y[2],2($inp)
	srl		@y[5],@x[0],16
	lb		@y[3],3($inp)
	srl		@y[6],@x[0],24
___
for(my $i=0; $i<15; $i++) {
my $j=4*$i;
my $k=4*($i+1);
$code.=<<___;
	xor		@x[$i],@x[$i],@y[0]
	lb		@y[0],$k+0($inp)
	xor		@y[4],@y[4],@y[1]
	lb		@y[1],$k+1($inp)
	xor		@y[5],@y[5],@y[2]
	lb		@y[2],$k+2($inp)
	xor		@y[6],@y[6],@y[3]
	lb		@y[3],$k+3($inp)
	sb		@x[$i],$j+0($out)
	sb		@y[4],$j+1($out)
	srl		@y[4],@x[$i+1],8
	sb		@y[5],$j+2($out)
	srl		@y[5],@x[$i+1],16
	sb		@y[6],$j+3($out)
	srl		@y[6],@x[$i+1],24
___
}
$code.=<<___;
	xor		@x[15],@x[15],@y[0]
	xor		@y[4],@y[4],@y[1]
	xor		@y[5],@y[5],@y[2]
	xor		@y[6],@y[6],@y[3]
	sb		@x[15],60($out)
	addi		$a5,$a5,1		# next counter value
	sb		@y[4],61($out)
	addi		$len,$len,-64
	sb		@y[5],62($out)
	caddi		$inp,$inp,64
	sb		@y[6],63($out)
	caddi		$out,$out,64
	beqz		$len,.Ldone

	sltiu		@y[4],$len,64
	li		$at,10
	jal		__ChaCha

	beqz		@y[4],.Loop_misaligned

	j		.Ltail
#endif

.Loop_aligned:
	lw		@y[0],0($inp)
	lw		@y[1],4($inp)
	lw		@y[2],8($inp)
	lw		@y[3],12($inp)
___
for (my $i=0; $i<12; $i+=4) {
my $j = 4*$i;
my $k = 4*($i+4);
$code.=<<___;
	xor		@x[$i+0],@x[$i+0],@y[0]
	lw		@y[0],$k+0($inp)
	xor		@x[$i+1],@x[$i+1],@y[1]
	lw		@y[1],$k+4($inp)
	xor		@x[$i+2],@x[$i+2],@y[2]
	lw		@y[2],$k+8($inp)
	xor		@x[$i+3],@x[$i+3],@y[3]
	lw		@y[3],$k+12($inp)
	sw		@x[$i+0],$j+0($out)
	sw		@x[$i+1],$j+4($out)
	sw		@x[$i+2],$j+8($out)
	sw		@x[$i+3],$j+12($out)
___
}
$code.=<<___;
	xor		@x[12],@x[12],@y[0]
	xor		@x[13],@x[13],@y[1]
	xor		@x[14],@x[14],@y[2]
	xor		@x[15],@x[15],@y[3]
	sw		@x[12],48($out)
	addi		$a5,$a5,1		# next counter value
	sw		@x[13],52($out)
	addi		$len,$len,-64
	sw		@x[14],56($out)
	caddi		$inp,$inp,64
	sw		@x[15],60($out)
	caddi		$out,$out,64
	sltiu		@y[4],$len,64
	beqz		$len,.Ldone

	li		$at,10
	jal		__ChaCha

	beqz		@y[4],.Loop_aligned

.Ltail:
	cmove		$ra,$sp
	sw		@x[1], 4*1($sp)
	sw		@x[2], 4*2($sp)
	sw		@x[3], 4*3($sp)
	sw		@x[4], 4*4($sp)
	sw		@x[5], 4*5($sp)
	sw		@x[6], 4*6($sp)
	sw		@x[7], 4*7($sp)
	sw		@x[8], 4*8($sp)
	sw		@x[9], 4*9($sp)
	sw		@x[10],4*10($sp)
	sw		@x[11],4*11($sp)
	sw		@x[12],4*12($sp)
	sw		@x[13],4*13($sp)
	sw		@x[14],4*14($sp)
	sw		@x[15],4*15($sp)

.Loop_tail:
	sltiu		$at,$len,4
	bnez		$at,.Last_word

	caddi		$ra,$ra,4
	lb		@y[0],0($inp)
	lb		@y[1],1($inp)
	lb		@y[2],2($inp)
	addi		$len,$len,-4
	lb		@y[3],3($inp)
	caddi		$inp,$inp,4
	xor		@y[0],@y[0],@x[0]
	srl		@x[0],@x[0],8
	xor		@y[1],@y[1],@x[0]
	srl		@x[0],@x[0],8
	xor		@y[2],@y[2],@x[0]
	srl		@x[0],@x[0],8
	xor		@y[3],@y[3],@x[0]
	lw		@x[0],0($ra)
	sb		@y[0],0($out)
	sb		@y[1],1($out)
	sb		@y[2],2($out)
	sb		@y[3],3($out)
	caddi		$out,$out,4
	j		.Loop_tail

.Last_word:
	beqz		$len,.Ldone
	addi		$len,$len,-1
	lb		@y[0],0($inp)
	caddi		$inp,$inp,1
	xor		@y[0],@y[0],@x[0]
	srl		@x[0],@x[0],8
	sb		@y[0],0($out)
	caddi		$out,$out,1
	j		.Last_word

.Ldone:
	POP		$ra, (FRAMESIZE-1*__SIZEOF_POINTER__)($sp)
	POP		$s0, (FRAMESIZE-2*__SIZEOF_POINTER__)($sp)
	POP		$s1, (FRAMESIZE-3*__SIZEOF_POINTER__)($sp)
	POP		$s2, (FRAMESIZE-4*__SIZEOF_POINTER__)($sp)
	POP		$s3, (FRAMESIZE-5*__SIZEOF_POINTER__)($sp)
	POP		$s4, (FRAMESIZE-6*__SIZEOF_POINTER__)($sp)
	POP		$s5, (FRAMESIZE-7*__SIZEOF_POINTER__)($sp)
	POP		$s6, (FRAMESIZE-8*__SIZEOF_POINTER__)($sp)
	POP		$s7, (FRAMESIZE-9*__SIZEOF_POINTER__)($sp)
	POP		$s8, (FRAMESIZE-10*__SIZEOF_POINTER__)($sp)
	POP		$s9, (FRAMESIZE-11*__SIZEOF_POINTER__)($sp)
	POP		$s10,(FRAMESIZE-12*__SIZEOF_POINTER__)($sp)
	POP		$s11,(FRAMESIZE-13*__SIZEOF_POINTER__)($sp)
	caddi		$sp,$sp,FRAMESIZE
	ret
.size	ChaCha20_ctr32,.-ChaCha20_ctr32
___

if (1) {{{
sub HROUND {
my ($a, $b, $c, $d, $t) = @_;

$code.=<<___
	vadd.vv		$a, $a, $b	# a += b
	vxor.vv		$d, $d, $a	# d ^= a
#ifdef	__riscv_zvbb
	vror.vi		$d, $d, 16
#else
	vsrl.vi		$t, $d, 16
	vsll.vi		$d, $d, 16
	vor.vv		$d, $d, $t	# d >>>= 16
#endif

	vadd.vv		$c, $c, $d	# c += d
	vxor.vv		$b, $b, $c	# b ^= c
#ifdef	__riscv_zvbb
	vror.vi		$b, $b, 20
#else
	vsrl.vi		$t, $b, 20
	vsll.vi		$b, $b, 12
	vor.vv		$b, $b, $t	# b >>>= 20
#endif

	vadd.vv		$a, $a, $b	# a += b
	vxor.vv		$d, $d, $a	# d ^= a
#ifdef	__riscv_zvbb
	vror.vi		$d, $d, 24
#else
	vsrl.vi		$t, $d, 24
	vsll.vi		$d, $d, 8
	vor.vv		$d, $d, $t	# d >>>= 24
#endif

	vadd.vv		$c, $c, $d	# c += d
	vxor.vv		$b, $b, $c	# b ^= c
#ifdef	__riscv_zvbb
	vror.vi		$b, $b, 25
#else
	vsrl.vi		$t, $b, 25
	vsll.vi		$b, $b, 7
	vor.vv		$b, $b, $t	# b >>>= 25
#endif
___
}

my $vtype=$t5;
my $vlenw=$t6;
my $MAX_WORDS=64;	# corresponds to 1024x2 bits

$code.=<<___;
#if defined(__riscv_v) && __riscv_v >= 1000000

#if defined(__riscv_zvkb) && !defined(__riscv_zvbb)
# define __riscv_zvbb __riscv_zvkb
#endif

.globl	ChaCha20_ctr32_v
.type	ChaCha20_ctr32_v,\@function
.align	2
ChaCha20_ctr32_v:
#ifdef	__riscv_zicfilp
	lpad		0
#endif
	li		$t0, 128
	bltu		$len, $t0, ChaCha20_ctr32

	vsetivli	$zero, 4, e32
	cllc		$t0, sigma

	caddi		$t1, $key, 16
	vle32.v		v2, ($key)	# b'
	vle32.v		v4, ($t1)	# c'
	vle32.v		v6, ($counter)	# d'

	li		$vlenw, $MAX_WORDS
	li		$vtype, 0x11	# e32, m2
#if 1
	vsetvli		$a5, $vlenw, e32, m2

	addi		$a6, $len, 63
	andi		$a6, $a6, -64
	addi		$a6, $a6, -1
	srli		$a6, $a6, 3
	sltu		$a7, $a6, $a5
	srli		$a5, $a5, 1
	sub		$vtype, $vtype, $a7
	sltu		$a7, $a6, $a5
	srli		$a5, $a5, 1
	sub		$vtype, $vtype, $a7
	sltu		$a7, $a6, $a5
	srli		$a5, $a5, 1
	sub		$vtype, $vtype, $a7
	sltu		$a7, $a6, $a5
	sub		$vtype, $vtype, $a7

	andi		$vtype, $vtype, 7
	ori		$vtype, $vtype, 0x10
#endif
	vsetvl		$vlenw, $vlenw, $vtype

	caddi		$t1, $t0, 1*$MAX_WORDS*4
	vle32.v		v16, ($t0)	# full-width a'
	caddi		$t2, $t0, 2*$MAX_WORDS*4
	vle32.v		v24, ($t1)	# >>>32
	caddi		$t3, $t0, 3*$MAX_WORDS*4
	vle32.v		v26, ($t2)	# >>>64
	caddi		$t4, $t0, 4*$MAX_WORDS*4
	vle32.v		v28, ($t3)	# >>>96
	vxor.vv		v30, v30, v30
	vle32.v		v8, ($t4)	# 128-bit broadcast

	lui		$t0, 0x11111
	srli		$t1, $vlenw, 2
	addi		$t0, $t0, 0x111
	vmv.v.x		v10, $t1
	vid.v		v12
	vmv.v.x		v0, $t0		# mask

	vrgather.vv	v18, v2, v8	# broadcast b'
	vrgather.vv	v20, v4, v8	# broadcast c'
	vrgather.vv	v22, v6, v8	# broadcast d'

	vsrl.vi		v12, v12, 2
	vor.vv		v30, v30, v10, v0.t
	vadd.vv		v22, v22, v12, v0.t

	li		$t0, 64

.Loop_outer_v:
	vmv.v.v		v0, v16		# a = a'
	vmv.v.v		v2, v18		# b = b'
	vmv.v.v		v4, v20		# c = c'
	vmv.v.v		v6, v22		# d = d'
	li		$a5, 10
.Loop_v:
___
	&HROUND(map("v$_", (0,2,4,6,8)));
$code.=<<___;
	vrgather.vv	v12, v6, v28	# d >>>= 96
	vrgather.vv	v8,  v2, v24	# b >>>= 32
	vrgather.vv	v10, v4, v26	# c >>>= 64
___
	&HROUND(map("v$_", (0,8,10,12,2)));
$code.=<<___;
	vrgather.vv	v6, v12, v24	# d >>>= 32
	vrgather.vv	v2, v8,  v28	# b >>>= 96
	vrgather.vv	v4, v10, v26	# c >>>= 64

	addi		$a5, $a5, -1
	bnez		$a5, .Loop_v

	vadd.vv		v8,  v0, v16	# a + a'
	vadd.vv		v10, v2, v18	# b + b'
	vadd.vv		v12, v4, v20	# c + c'
	vadd.vv		v14, v6, v22	# d + d'
	vadd.vv		v22, v22, v30	# advance the counter

	caddi		$t1, $inp, 16
	caddi		$t2, $inp, 32
	caddi		$t3, $inp, 48
	li		$t4, 0
	j		.Loop_xor_v_jump_in

.Loop_xor_v:
	vslidedown.vi	v8,  v8,  4
	vslidedown.vi	v10, v10, 4
	vslidedown.vi	v12, v12, 4
	vslidedown.vi	v14, v14, 4
.Loop_xor_v_jump_in:
	vsetivli	zero, 16, e8
	bltu		$len, $t0, .Ltail_v

	vle8.v		v0, ($inp)
	addi		$len, $len, -64
	vle8.v		v1, ($t1)
	caddi		$t1, $out, 16
	vle8.v		v2, ($t2)
	caddi		$t2, $out, 32
	vle8.v		v3, ($t3)
	caddi		$t3, $out, 48
	vxor.vv		v0, v0, v8
	vxor.vv		v1, v1, v10
	vxor.vv		v2, v2, v12
	vxor.vv		v3, v3, v14
	caddi		$inp, $inp, 64
	vse8.v		v0, ($out)
	caddi		$out, $out, 64
	vse8.v		v1, ($t1)
	caddi		$t1, $inp, 16
	vse8.v		v2, ($t2)
	caddi		$t2, $inp, 32
	vse8.v		v3, ($t3)
	caddi		$t3, $inp, 48
	addi		$t4, $t4, 4
	beqz		$len, .Ldone_v

	vsetvl		zero, $vlenw, $vtype
	bltu		$t4, $vlenw, .Loop_xor_v

	j		.Loop_outer_v

.Ltail_v:
	li		$t0, 16
	bleu		$len, $t0, .Last_v

	vle8.v		v0, ($inp)
	caddi		$inp, $inp, 16
	addi		$len, $len, -16
	vxor.vv		v0, v0, v8
	vmv.v.v		v8, v10
	vse8.v		v0, ($out)
	caddi		$out, $out, 16
	bleu		$len, $t0, .Last_v

	vle8.v		v1, ($inp)
	caddi		$inp, $inp, 16
	addi		$len, $len, -16
	vxor.vv		v1, v1, v10
	vmv.v.v		v8, v12
	vse8.v		v1, ($out)
	caddi		$out, $out, 16
	bleu		$len, $t0, .Last_v

	vle8.v		v2, ($inp)
	caddi		$inp, $inp, 16
	addi		$len, $len, -16
	vxor.vv		v2, v2, v12
	vmv.v.v		v8, v14
	vse8.v		v2, ($out)
	caddi		$out, $out, 16

.Last_v:
	vsetvli		zero, $len, e8
	vle8.v		v3, ($inp)
	vxor.vv		v3, v3, v8
	vse8.v		v3, ($out)

.Ldone_v:
	ret
.size	ChaCha20_ctr32_v,.-ChaCha20_ctr32_v

.section	.rodata
.align	4
sigma:
___
for (my $i=0; $i<$MAX_WORDS; $i+=4) {
$code.=<<___;
.word	0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
___
}
# 128-bit >>>32
for (my $i=0; $i<$MAX_WORDS; $i+=4) {
$code.=<<___;
.word	1+$i, 2+$i, 3+$i, 0+$i
___
}
# 128-bit >>>64
for (my $i=0; $i<$MAX_WORDS; $i+=4) {
$code.=<<___;
.word	2+$i, 3+$i, 0+$i, 1+$i
___
}
# 128-bit >>>96
for (my $i=0; $i<$MAX_WORDS; $i+=4) {
$code.=<<___;
.word	3+$i, 0+$i, 1+$i, 2+$i
___
}
# 128-bit broadcast
for (my $i=0; $i<$MAX_WORDS; $i+=4) {
$code.=<<___;
.word	0, 1, 2, 3
___
}
$code.=<<___;
#endif
___
}}}

if (1) {{{
my ($vtype, $vlenw, $vlenb) = ($t4, $t5, $counter);

sub VROUNDm1 {
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));

$code.=<<___;
	vsetvli		$zero, $vlenw, e32, m1

	vadd.vv		v$a0,v$a0,v$b0		# Q0
	 vadd.vv	v$a1,v$a1,v$b1		# Q1
	  vadd.vv	v$a2,v$a2,v$b2		# Q2
	   vadd.vv	v$a3,v$a3,v$b3		# Q3
	vxor.vv		v$d0,v$d0,v$a0
	 vxor.vv	v$d1,v$d1,v$a1
	  vxor.vv	v$d2,v$d2,v$a2
	   vxor.vv	v$d3,v$d3,v$a3
#ifdef	__riscv_zvbb
	vror.vi		v$d0,v$d0,16
	 vror.vi	v$d1,v$d1,16
	  vror.vi	v$d2,v$d2,16
	   vror.vi	v$d3,v$d3,16
#else
	vsrl.vi		v16,v$d0,16
	 vsrl.vi	v17,v$d1,16
	  vsrl.vi	v18,v$d2,16
	   vsrl.vi	v19,v$d3,16
	vsll.vi		v$d0,v$d0,16
	 vsll.vi	v$d1,v$d1,16
	  vsll.vi	v$d2,v$d2,16
	   vsll.vi	v$d3,v$d3,16
	vor.vv		v$d0,v$d0,v16
	 vor.vv		v$d1,v$d1,v17
	  vor.vv	v$d2,v$d2,v18
	   vor.vv	v$d3,v$d3,v19
#endif

	vadd.vv		v$c0,v$c0,v$d0
	 vadd.vv	v$c1,v$c1,v$d1
	  vadd.vv	v$c2,v$c2,v$d2
	   vadd.vv	v$c3,v$c3,v$d3
	vxor.vv		v$b0,v$b0,v$c0
	 vxor.vv	v$b1,v$b1,v$c1
	  vxor.vv	v$b2,v$b2,v$c2
	   vxor.vv	v$b3,v$b3,v$c3
#ifdef	__riscv_zvbb
	vror.vi		v$b0,v$b0,20
	 vror.vi	v$b1,v$b1,20
	  vror.vi	v$b2,v$b2,20
	   vror.vi	v$b3,v$b3,20
#else
	vsrl.vi		v16,v$b0,20
	 vsrl.vi	v17,v$b1,20
	  vsrl.vi	v18,v$b2,20
	   vsrl.vi	v19,v$b3,20
	vsll.vi		v$b0,v$b0,12
	 vsll.vi	v$b1,v$b1,12
	  vsll.vi	v$b2,v$b2,12
	   vsll.vi	v$b3,v$b3,12
	vor.vv		v$b0,v$b0,v16
	 vor.vv		v$b1,v$b1,v17
	  vor.vv	v$b2,v$b2,v18
	   vor.vv	v$b3,v$b3,v19
#endif

	vadd.vv		v$a0,v$a0,v$b0
	 vadd.vv	v$a1,v$a1,v$b1
	  vadd.vv	v$a2,v$a2,v$b2
	   vadd.vv	v$a3,v$a3,v$b3
	vxor.vv		v$d0,v$d0,v$a0
	 vxor.vv	v$d1,v$d1,v$a1
	  vxor.vv	v$d2,v$d2,v$a2
	   vxor.vv	v$d3,v$d3,v$a3
#ifdef	__riscv_zvbb
	vror.vi		v$d0,v$d0,24
	 vror.vi	v$d1,v$d1,24
	  vror.vi	v$d2,v$d2,24
	   vror.vi	v$d3,v$d3,24
#else
	vsrl.vi		v16,v$d0,24
	 vsrl.vi	v17,v$d1,24
	  vsrl.vi	v18,v$d2,24
	   vsrl.vi	v19,v$d3,24
	vsll.vi		v$d0,v$d0,8
	 vsll.vi	v$d1,v$d1,8
	  vsll.vi	v$d2,v$d2,8
	   vsll.vi	v$d3,v$d3,8
	vor.vv		v$d0,v$d0,v16
	 vor.vv		v$d1,v$d1,v17
	  vor.vv	v$d2,v$d2,v18
	   vor.vv	v$d3,v$d3,v19
#endif

	vadd.vv		v$c0,v$c0,v$d0
	 vadd.vv	v$c1,v$c1,v$d1
	  vadd.vv	v$c2,v$c2,v$d2
	   vadd.vv	v$c3,v$c3,v$d3
	vxor.vv		v$b0,v$b0,v$c0
	 vxor.vv	v$b1,v$b1,v$c1
	  vxor.vv	v$b2,v$b2,v$c2
	   vxor.vv	v$b3,v$b3,v$c3
#ifdef	__riscv_zvbb
	vror.vi		v$b0,v$b0,25
	 vror.vi	v$b1,v$b1,25
	  vror.vi	v$b2,v$b2,25
	   vror.vi	v$b3,v$b3,25
#else
	vsrl.vi		v16,v$b0,25
	 vsrl.vi	v17,v$b1,25
	  vsrl.vi	v18,v$b2,25
	   vsrl.vi	v19,v$b3,25
	vsll.vi		v$b0,v$b0,7
	 vsll.vi	v$b1,v$b1,7
	  vsll.vi	v$b2,v$b2,7
	   vsll.vi	v$b3,v$b3,7
	vor.vv		v$b0,v$b0,v16
	 vor.vv		v$b1,v$b1,v17
	  vor.vv	v$b2,v$b2,v18
	   vor.vv	v$b3,v$b3,v19
#endif
___
}

sub VROUNDm4 {
my ($a0,$b0,$c0,$d0)=@_;

$code.=<<___;
	vsetvli		$zero, $vlenb, e32, m4

	vadd.vv		v$a0,v$a0,v$b0		# Q0-Q3
	vxor.vv		v$d0,v$d0,v$a0
#ifdef	__riscv_zvbb
	vror.vi		v$d0,v$d0,16
#else
	vsrl.vi		v16,v$d0,16
	vsll.vi		v$d0,v$d0,16
	vor.vv		v$d0,v$d0,v16
#endif

	vadd.vv		v$c0,v$c0,v$d0
	vxor.vv		v$b0,v$b0,v$c0
#ifdef	__riscv_zvbb
	vror.vi		v$b0,v$b0,20
#else
	vsrl.vi		v16,v$b0,20
	vsll.vi		v$b0,v$b0,12
	vor.vv		v$b0,v$b0,v16
#endif

	vadd.vv		v$a0,v$a0,v$b0
	vxor.vv		v$d0,v$d0,v$a0
#ifdef	__riscv_zvbb
	vror.vi		v$d0,v$d0,24
#else
	vsrl.vi		v16,v$d0,24
	vsll.vi		v$d0,v$d0,8
	vor.vv		v$d0,v$d0,v16
#endif

	vadd.vv		v$c0,v$c0,v$d0
	vxor.vv		v$b0,v$b0,v$c0
#ifdef	__riscv_zvbb
	vror.vi		v$b0,v$b0,25
#else
	vsrl.vi		v16,v$b0,25
	vsll.vi		v$b0,v$b0,7
	vor.vv		v$b0,v$b0,v16
#endif
___
}

my @sigma = map("x$_",(15..17,31));

$code.=<<___;
#if defined(__riscv_v) && __riscv_v >= 1000000

#if defined(__riscv_zvkb) && !defined(__riscv_zvbb)
# define __riscv_zvbb __riscv_zvkb
#endif

.text

.globl	ChaCha20_ctr32_vx
.type	ChaCha20_ctr32_vx,\@function
.align	2
ChaCha20_ctr32_vx:
#ifdef	__riscv_zicfilp
	lpad		0
#endif
	li		$t0, 256
#ifdef	__riscv_zbb
	bleu		$len, $t0, ChaCha20_ctr32
#else
	bleu		$len, $t0, ChaCha20_ctr32_v
#endif
	caddi		$sp, $sp, -FRAMESIZE
	PUSH		$ra, (FRAMESIZE-1*__SIZEOF_POINTER__)($sp)
	PUSH		$s0, (FRAMESIZE-2*__SIZEOF_POINTER__)($sp)
	cmove		$s0, $sp

	li		$vlenw, -1		# ask for "infinite" vlen
	vsetvli		$vlenw, $vlenw, e32	# get actual vlen [in words]
	sll		$t0, $vlenw, 2+4	# vlen in bytes times 16

	li		$vtype, 0x10		# e32, m1
	sltiu		$t1, $vlenw, 8
	sltiu		$t2, $vlenw, 16
	add		$vtype, $vtype, $t1	# adjust lmul to accommodate 64 bytes
	add		$vtype, $vtype, $t2

#ifdef	__CHERI_PURE_CAPABILITY__
	neg		$t0, $t0
	cadd		$sp, $sp, $t0		# storage for transposition
#else
	sub		$sp, $sp, $t0		# storage for transposition
#endif

	lui		@sigma[0],0x61707+1	# compose sigma
	lui		@sigma[1],0x33206
	lui		@sigma[2],0x79622+1
	lui		@sigma[3],0x6b206
	addi		@sigma[0],@sigma[0],-0x79b
	addi		@sigma[1],@sigma[1],0x46e
	addi		@sigma[2],@sigma[2],-0x2ce
	addi		@sigma[3],@sigma[3],0x574

	lw		$t0, 4*0($key)		# load key
	lw		$t1, 4*1($key)
	lw		$t2, 4*2($key)
	lw		$t3, 4*3($key)

	vmv.v.x		v20, $t0
	lw		$t0, 4*4($key)
	vmv.v.x		v21, $t1
	lw		$t1, 4*5($key)
	vmv.v.x		v22, $t2
	lw		$t2, 4*6($key)
	vmv.v.x		v23, $t3
	lw		$t3, 4*7($key)
	vmv.v.x		v24, $t0
	lw		$t0, 4*0($counter)	# load counter
	vmv.v.x		v25, $t1
	lw		$t1, 4*1($counter)
	vmv.v.x		v26, $t2
	lw		$t2, 4*2($counter)
	vmv.v.x		v27, $t3
	lw		$t3, 4*3($counter)
	vmv.v.x		v29, $t1
	sw		$t1, 4*1($s0)		# in case we call the scalar version
	vmv.v.x		v30, $t2
	sw		$t2, 4*2($s0)
	vmv.v.x		v31, $t3
	sw		$t3, 4*3($s0)
	vid.v		v28			# initial counter increment
	sll		$vlenb, $vlenw, 2

.Loop_outer_vx:
	vmv.v.x		v0, @sigma[0]
	vmv.v.x		v1, @sigma[1]
	vmv.v.x		v2, @sigma[2]
	vmv.v.x		v3, @sigma[3]
	vadd.vx		v28, v28, $t0		# advance the counter
	vmv.v.v		v4, v20
	vmv.v.v		v5, v21
	vmv.v.v		v6, v22
	vmv.v.v		v7, v23
	vmv.v.v		v8, v24
	vmv.v.v		v9, v25
	vmv.v.v		v10, v26
	vmv.v.v		v11, v27
	vmv.v.v		v12, v28
	vmv.v.v		v13, v29
	vmv.v.v		v14, v30
	vmv.v.v		v15, v31

	li		$t0, 10
.Loop_vx:
	addi		$t0, $t0, -1
___
	&VROUNDm4(0, 4, 8, 12);
	&VROUNDm1(0, 5, 10, 15);
$code.=<<___;
	bnez		$t0, .Loop_vx

	vadd.vx		v0,  v0,  @sigma[0]
	vadd.vx		v1,  v1,  @sigma[1]
	vadd.vx		v2,  v2,  @sigma[2]
	vadd.vx		v3,  v3,  @sigma[3]
	vsetvli		$zero, $vlenb, e32, m4
	vadd.vv		v4,  v4,  v20
	sll		$t3, $vlenb, 2
	vadd.vv		v8,  v8,  v24
	cadd		$t0, $sp, $t3
	vadd.vv		v12, v12, v28
	cadd		$t1, $t0, $t3

	vse32.v		v0, ($sp)		# offload for transposition
	cadd		$t2, $t1, $t3
	vse32.v		v4, ($t0)
	cmove		$t0, $sp
	vse32.v		v8, ($t1)
	add		$t1, $sp, $vlenb
	vse32.v		v12, ($t2)
	li		$t2, 16
	li		$t3, 64
.Loop_xor_vx:
	vsetvl		$zero, $t2, $vtype	# e32
	andi		$vtype, $vtype, -0x11	# clear e32
	vlse32.v	v0, ($t0), $vlenb	# gather 64 bytes
	bleu		$len, $t3, .Ltail_vx

	vsetvl		$zero, $t3, $vtype	# e8
	ori		$vtype, $vtype, 0x10	# set e32
	vle8.v		v4, ($inp)		# load 64 bytes of input
	cadd		$inp, $inp, $t3
	sub		$len, $len, $t3
	caddi		$t0, $t0, 4
	vxor.vv		v0, v0, v4
	vse8.v		v0, ($out)		# store 64 bytes of output
	cadd		$out, $out, $t3
	bltu		$t0, $t1, .Loop_xor_vx

	vsetvli		$zero, $vlenw, e32
	mv		$t0, $vlenw
	li		$t1, 256
	vmv.x.s		$t2, v28		# in case we call the scalar version
#if 0
	bnez		$len, .Loop_outer_vx
#else
	bgtu		$len, $t1, .Loop_outer_vx

	add		$t2, $t2, $t0		# advance the counter
	cmove		$counter, $s0
	cmove		$sp, $s0
	sw		$t2, ($s0)
	j		.Lscalar_shortcut
#endif

.Ltail_vx:
	vsetvl		$zero, $len, $vtype	# e8
	vle8.v		v4, ($inp)
	vxor.vv		v4, v4, v0
	vse8.v		v4, ($out)

.Ldone_vx:
	cmove		$sp, $s0
	POP		$s0, (FRAMESIZE-2*__SIZEOF_POINTER__)($s0)
	caddi		$sp, $sp, FRAMESIZE
	ret
.size	ChaCha20_ctr32_vx,.-ChaCha20_ctr32_vx
#endif
___
}}}

$code.=<<___;
.section	.rodata
.align	3
.string	"ChaCha20 for RISC-V, CRYPTOGAMS by \@dot-asm"
___

foreach (split("\n", $code)) {
    if ($flavour =~ "cheri") {
	s/\(x([0-9]+)\)/(c$1)/ and s/\b([ls][bhwd]u?)\b/c$1/;
	s/\b(PUSH|POP|cllc)(\s+)x([0-9]+)/$1$2c$3/ or
	s/\b(ret|jal)\b/c$1/;
	s/\bcaddi?\b/cincoffset/ and s/\bx([0-9]+,)/c$1/g or
	m/\bcmove\b/ and s/\bx([0-9]+)/c$1/g;
    } else {
	s/\bcaddi?\b/add/ or
	s/\bcllc\b/lla/ or
	s/\bcmove\b/mv/;
    }
    print $_, "\n";
}

close STDOUT;

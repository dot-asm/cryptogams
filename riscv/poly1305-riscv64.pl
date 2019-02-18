#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use with OpenSSL.
# ====================================================================
#
# Poly1305 hash for RISC-V.
#
# February 2019
#
# In the essence it's pretty straightforward transliteration of MIPS
# module [without big-endian option].
#
######################################################################
#
($zero,$ra,$sp,$gp,$tp)=map("x$_",(0..4));
($t0,$t1,$t2,$t3,$t4,$t5,$t6)=map("x$_",(5..7,28..31));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("x$_",(10..17));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8,$s9,$s10,$s11)=map("x$_",(8,9,18..27));
#
######################################################################

($ctx,$inp,$len,$padbit) = ($a0,$a1,$a2,$a3);
($in0,$in1,$tmp0,$tmp1,$tmp2,$tmp3,$tmp4) = ($a4,$a5,$a6,$a7,$t0,$t1,$t2);

$code.=<<___;
.option	pic
.text

.globl	poly1305_init
.type	poly1305_init,\@function
.align	1
poly1305_init:
	sd	$zero,0($ctx)
	sd	$zero,8($ctx)
	sd	$zero,16($ctx)

	beqz	$inp,.Lno_key

	andi	$tmp0,$inp,7		# $inp % 8
	andi	$inp,$inp,-8		# align $inp
	slli	$tmp0,$tmp0,3		# byte to bit offset
	ld	$in0,0($inp)
	ld	$in1,8($inp)
	beqz	$tmp0,.Laligned_key

	ld	$tmp2,16($inp)
	neg	$tmp1,$tmp0		# implicit &63 in sll
	srl	$in0,$in0,$tmp0
	sll	$tmp3,$in1,$tmp1
	srl	$in1,$in1,$tmp0
	sll	$tmp2,$tmp2,$tmp1
	or	$in0,$in0,$tmp3
	or	$in1,$in1,$tmp2

.Laligned_key:
	li	$tmp0,1
	slli	$tmp0,$tmp0,32		# 0x0000000100000000
	addi	$tmp0,$tmp0,-63		# 0x00000000ffffffc1
	slli	$tmp0,$tmp0,28		# 0x0ffffffc10000000
	addi	$tmp0,$tmp0,-1		# 0x0ffffffc0fffffff

	and	$in0,$in0,$tmp0
	addi	$tmp0,$tmp0,-3		# 0x0ffffffc0ffffffc
	and	$in1,$in1,$tmp0

	sd	$in0,24($ctx)
	srli	$tmp0,$in1,2
	sd	$in1,32($ctx)
	add	$tmp0,$tmp0,$in1	# s1 = r1 + (r1 >> 2)
	sd	$tmp0,40($ctx)

.Lno_key:
	li	$a0,0			# return 0
	ret
.size	poly1305_init,.-poly1305_init
___
{
my ($h0,$h1,$h2,$r0,$r1,$rs1,$d0,$d1,$d2) =
   ($s0,$s1,$s2,$s3,$t3,$t4,$in0,$in1,$t2);
my ($shr,$shl) = ($t5,$t6);		# used on R6

$code.=<<___;
.globl	poly1305_blocks
.type	poly1305_blocks,\@function
poly1305_blocks:
	srli	$len,$len,4		# number of complete blocks
	beqz	$len,.Lno_data

	addi	$sp,$sp,-32
	sd	$s0,24($sp)
	sd	$s1,16($sp)
	sd	$s2,8($sp)
	sd	$s3,0($sp)

	ld	$h0,0($ctx)		# load hash value
	ld	$h1,8($ctx)
	ld	$h2,16($ctx)

	ld	$r0,24($ctx)		# load key
	ld	$r1,32($ctx)
	ld	$rs1,40($ctx)

	andi	$shr,$inp,7
	andi	$inp,$inp,-8		# align $inp
	slli	$shr,$shr,3		# byte to bit offset
	neg	$shl,$shr		# implicit &63 in sll

.Loop:
	ld	$in0,0($inp)		# load input
	ld	$in1,8($inp)
	beqz	$shr,.Laligned_inp

	ld	$tmp2,16($inp)
	srl	$in0,$in0,$shr
	sll	$tmp3,$in1,$shl
	srl	$in1,$in1,$shr
	sll	$tmp2,$tmp2,$shl
	or	$in0,$in0,$tmp3
	or	$in1,$in1,$tmp2

.Laligned_inp:
	addi	$len,$len,-1
	addi	$inp,$inp,16

	add	$h0,$h0,$in0		# accumulate input
	add	$h1,$h1,$in1
	sltu	$tmp0,$h0,$in0
	sltu	$tmp1,$h1,$in1
	add	$h1,$h1,$tmp0

	 add	$h2,$h2,$padbit
	 sltu	$tmp0,$h1,$tmp0
	mulhu	$d1,$r0,$h0		# h0*r0
	mul	$d0,$r0,$h0

	 add	$tmp0,$tmp0,$tmp1
	 add	$h2,$h2,$tmp0
	mulhu	$tmp1,$rs1,$h1		# h1*5*r1
	mul	$tmp0,$rs1,$h1

	 add	$d0,$d0,$tmp0
	 add	$d1,$d1,$tmp1
	mulhu	$d2,$r1,$h0		# h0*r1
	mul	$tmp2,$r1,$h0
	 sltu	$tmp0,$d0,$tmp0
	 add	$d1,$d1,$tmp0

	 add	$d1,$d1,$tmp2
	 sltu	$tmp2,$d1,$tmp2
	mulhu	$tmp1,$r0,$h1		# h1*r0
	mul	$tmp0,$r0,$h1
	 add	$d2,$d2,$tmp2

	 add	$d1,$d1,$tmp0
	 add	$d2,$d2,$tmp1
	mul	$tmp2,$rs1,$h2		# h2*5*r1

	 sltu	$tmp0,$d1,$tmp0
	 add	$d2,$d2,$tmp0
	mul	$tmp3,$r0,$h2		# h2*r0

	add	$d1,$d1,$tmp2
	add	$d2,$d2,$tmp3
	sltu	$tmp2,$d1,$tmp2
	add	$d2,$d2,$tmp2

	andi	$tmp0,$d2,-4		# final reduction
	srli	$tmp1,$d2,2
	andi	$h2,$d2,3
	add	$tmp0,$tmp0,$tmp1
	add	$h0,$d0,$tmp0
	sltu	$tmp0,$h0,$tmp0
	add	$h1,$d1,$tmp0
	sltu	$tmp0,$h1,$tmp0
	add	$h2,$h2,$tmp0

	bnez	$len,.Loop

	sd	$h0,0($ctx)		# store hash value
	sd	$h1,8($ctx)
	sd	$h2,16($ctx)

	ld	$s0,24($sp)		# epilogue
	ld	$s1,16($sp)
	ld	$s2,8($sp)
	ld	$s3,0($sp)
	addi	$sp,$sp,32

.Lno_data:
	ret
.size	poly1305_blocks,.-poly1305_blocks
___
}
{
my ($ctx,$mac,$nonce) = ($a0,$a1,$a2);

$code.=<<___;
.globl	poly1305_emit
.type	poly1305_emit,\@function
poly1305_emit:
	ld	$tmp0,0($ctx)
	ld	$tmp1,8($ctx)
	ld	$tmp2,16($ctx)

	addi	$in0,$tmp0,5		# compare to modulus
	sltiu	$tmp3,$in0,5
	add	$in1,$tmp1,$tmp3
	sltu	$tmp3,$in1,$tmp3
	add	$tmp2,$tmp2,$tmp3

	srli	$tmp2,$tmp2,2		# see if it carried/borrowed
	neg	$tmp2,$tmp2

	xor	$in0,$in0,$tmp0
	xor	$in1,$in1,$tmp1
	and	$in0,$in0,$tmp2
	and	$in1,$in1,$tmp2
	xor	$in0,$in0,$tmp0
	xor	$in1,$in1,$tmp1

	lwu	$tmp0,0($nonce)		# load nonce
	lwu	$tmp1,4($nonce)
	lwu	$tmp2,8($nonce)
	lwu	$tmp3,12($nonce)
	slli	$tmp1,$tmp1,32
	slli	$tmp3,$tmp3,32
	or	$tmp0,$tmp0,$tmp1
	or	$tmp2,$tmp2,$tmp3

	add	$in0,$in0,$tmp0		# accumulate nonce
	add	$in1,$in1,$tmp2
	sltu	$tmp0,$in0,$tmp0
	add	$in1,$in1,$tmp0

	srli	$tmp0,$in0,8		# write mac value
	srli	$tmp1,$in0,16
	srli	$tmp2,$in0,24
	sb	$in0,0($mac)
	srli	$tmp3,$in0,32
	sb	$tmp0,1($mac)
	srli	$tmp0,$in0,40
	sb	$tmp1,2($mac)
	srli	$tmp1,$in0,48
	sb	$tmp2,3($mac)
	srli	$tmp2,$in0,56
	sb	$tmp3,4($mac)
	srli	$tmp3,$in1,8
	sb	$tmp0,5($mac)
	srli	$tmp0,$in1,16
	sb	$tmp1,6($mac)
	srli	$tmp1,$in1,24
	sb	$tmp2,7($mac)

	sb	$in1,8($mac)
	srli	$tmp2,$in1,32
	sb	$tmp3,9($mac)
	srli	$tmp3,$in1,40
	sb	$tmp0,10($mac)
	srli	$tmp0,$in1,48
	sb	$tmp1,11($mac)
	srli	$tmp1,$in1,56
	sb	$tmp2,12($mac)
	sb	$tmp3,13($mac)
	sb	$tmp0,14($mac)
	sb	$tmp1,15($mac)

	ret
.size	poly1305_emit,.-poly1305_emit
.string	"Poly1305 for RISC-V, CRYPTOGAMS by \@dot-asm"
___
}

$output=pop and open STDOUT,">$output";
print $code;
close STDOUT;


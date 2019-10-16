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

$flavour = shift || "64";

for (@ARGV) {   $output=$_ if (/\w[\w\-]*\.\w+$/);   }
open STDOUT,">$output";

if ($flavour =~ /64/) {{{
######################################################################
# 64-bit code path...
#
my ($ctx,$inp,$len,$padbit) = ($a0,$a1,$a2,$a3);
my ($in0,$in1,$tmp0,$tmp1,$tmp2,$tmp3,$tmp4) = ($a4,$a5,$a6,$a7,$t0,$t1,$t2);

$code.=<<___;
.option	pic
.text

.globl	poly1305_init
.type	poly1305_init,\@function
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

	andi	$shr,$inp,7
	andi	$inp,$inp,-8		# align $inp
	slli	$shr,$shr,3		# byte to bit offset
	neg	$shl,$shr		# implicit &63 in sll

	ld	$h0,0($ctx)		# load hash value
	ld	$h1,8($ctx)
	ld	$h2,16($ctx)

	ld	$r0,24($ctx)		# load key
	ld	$r1,32($ctx)
	ld	$rs1,40($ctx)

	slli	$len,$len,4
	add	$len,$len,$inp		# end of buffer

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
	addi	$inp,$inp,16

	andi	$tmp0,$h2,-4		# modulo-scheduled reduction
	srli	$tmp1,$h2,2
	andi	$h2,$h2,3

	add	$d0,$h0,$in0		# accumulate input
	 add	$tmp1,$tmp1,$tmp0
	sltu	$tmp0,$d0,$h0
	add	$d0,$d0,$tmp1		# ... and residue
	sltu	$tmp1,$d0,$tmp1
	add	$d1,$h1,$in1
	add	$tmp0,$tmp0,$tmp1
	sltu	$tmp1,$d1,$h1
	add	$d1,$d1,$tmp0

	 add	$d2,$h2,$padbit
	 sltu	$tmp0,$d1,$tmp0
	mulhu	$h1,$r0,$d0		# h0*r0
	mul	$h0,$r0,$d0

	 add	$d2,$d2,$tmp1
	 add	$d2,$d2,$tmp0
	mulhu	$tmp1,$rs1,$d1		# h1*5*r1
	mul	$tmp0,$rs1,$d1

	mulhu	$h2,$r1,$d0		# h0*r1
	mul	$tmp2,$r1,$d0
	 add	$h0,$h0,$tmp0
	 add	$h1,$h1,$tmp1
	 sltu	$tmp0,$h0,$tmp0

	 add	$h1,$h1,$tmp0
	 add	$h1,$h1,$tmp2
	mulhu	$tmp1,$r0,$d1		# h1*r0
	mul	$tmp0,$r0,$d1

	 sltu	$tmp2,$h1,$tmp2
	 add	$h2,$h2,$tmp2
	mul	$tmp2,$rs1,$d2		# h2*5*r1

	 add	$h1,$h1,$tmp0
	 add	$h2,$h2,$tmp1
	mul	$tmp3,$r0,$d2		# h2*r0
	 sltu	$tmp0,$h1,$tmp0
	 add	$h2,$h2,$tmp0

	add	$h1,$h1,$tmp2
	sltu	$tmp2,$h1,$tmp2
	add	$h2,$h2,$tmp2
	add	$h2,$h2,$tmp3

	bne	$inp,$len,.Loop

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
	ld	$tmp2,16($ctx)
	ld	$tmp0,0($ctx)
	ld	$tmp1,8($ctx)

	andi	$in0,$tmp2,-4		# final reduction
	srl	$in1,$tmp2,2
	andi	$tmp2,$tmp2,3
	add	$in0,$in0,$in1

	add	$tmp0,$tmp0,$in0
	sltu	$in1,$tmp0,$in0
	 addi	$in0,$tmp0,5		# compare to modulus
	add	$tmp1,$tmp1,$in1
	 sltiu	$tmp3,$in0,5
	sltu	$tmp4,$tmp1,$in1
	 add	$in1,$tmp1,$tmp3
	add	$tmp2,$tmp2,$tmp4
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
}}} else {{{
######################################################################
# 32-bit code path
#

my ($ctx,$inp,$len,$padbit) = ($a0,$a1,$a2,$a3);
my ($in0,$in1,$in2,$in3,$tmp0,$tmp1,$tmp2,$tmp3) =
   ($a4,$a5,$a6,$a7,$t0,$t1,$t2,$t3);

$code.=<<___;
.option	pic
.text

.globl	poly1305_init
.type	poly1305_init,\@function
poly1305_init:
	sw	$zero,0($ctx)
	sw	$zero,4($ctx)
	sw	$zero,8($ctx)
	sw	$zero,12($ctx)
	sw	$zero,16($ctx)

	beqz	$inp,.Lno_key

	andi	$tmp0,$inp,3		# $inp % 4
	sub	$inp,$inp,$tmp0		# align $inp
	sll	$tmp0,$tmp0,3		# byte to bit offset
	lw	$in0,0($inp)
	lw	$in1,4($inp)
	lw	$in2,8($inp)
	lw	$in3,12($inp)
	beqz	$tmp0,.Laligned_key

	lw	$tmp2,16($inp)
	sub	$tmp1,$zero,$tmp0
	srl	$in0,$in0,$tmp0
	sll	$tmp3,$in1,$tmp1
	srl	$in1,$in1,$tmp0
	or	$in0,$in0,$tmp3
	sll	$tmp3,$in2,$tmp1
	srl	$in2,$in2,$tmp0
	or	$in1,$in1,$tmp3
	sll	$tmp3,$in3,$tmp1
	srl	$in3,$in3,$tmp0
	or	$in2,$in2,$tmp3
	sll	$tmp2,$tmp2,$tmp1
	or	$in3,$in3,$tmp2
.Laligned_key:

	lui	$tmp0,0x10000
	addi	$tmp0,$tmp0,-1		# 0x0fffffff
	and	$in0,$in0,$tmp0
	addi	$tmp0,$tmp0,-3		# 0x0ffffffc
	and	$in1,$in1,$tmp0
	and	$in2,$in2,$tmp0
	and	$in3,$in3,$tmp0

	sw	$in0,20($ctx)
	sw	$in1,24($ctx)
	sw	$in2,28($ctx)
	sw	$in3,32($ctx)

	srl	$tmp1,$in1,2
	srl	$tmp2,$in2,2
	srl	$tmp3,$in3,2
	add	$in1,$in1,$tmp1		# s1 = r1 + (r1 >> 2)
	add	$in2,$in2,$tmp2
	add	$in3,$in3,$tmp3
	sw	$in1,36($ctx)
	sw	$in2,40($ctx)
	sw	$in3,44($ctx)
.Lno_key:
	li	$a0,0
	ret
.size	poly1305_init,.-poly1305_init
___
{
my ($h0,$h1,$h2,$h3,$h4, $r0,$r1,$r2,$r3, $rs1,$rs2,$rs3) =
   ($s0,$s1,$s2,$s3,$s4, $s5,$s6,$s7,$s8, $t0,$t1,$t2);
my ($d0,$d1,$d2,$d3) =
   ($a4,$a5,$a6,$a7);
my $shr = $ra;		# used on R6

$code.=<<___;
.globl	poly1305_blocks
.type	poly1305_blocks,\@function
poly1305_blocks:
	srli	$len,$len,4		# number of complete blocks
	bnez	$len,.Labort
	addi	$sp,$sp,-4*12
	sw	$ra, 4*11($sp)
	sw	$s0, 4*10($sp)
	sw	$s1, 4*9($sp)
	sw	$s2, 4*8($sp)
	sw	$s3, 4*7($sp)
	sw	$s4, 4*6($sp)
	sw	$s5, 4*5($sp)
	sw	$s6, 4*4($sp)
	sw	$s7, 4*3($sp)
	sw	$s8, 4*2($sp)

	andi	$shr,$inp,3
	andi	$inp,$inp,-8		# align $inp
	slli	$shr,$shr,3		# byte to bit offset

	lw	$h0,0($ctx)		# load hash value
	lw	$h1,4($ctx)
	lw	$h2,8($ctx)
	lw	$h3,12($ctx)
	lw	$h4,16($ctx)

	lw	$r0,20($ctx)		# load key
	lw	$r1,24($ctx)
	lw	$r2,28($ctx)
	lw	$r3,32($ctx)
	lw	$rs1,36($ctx)
	lw	$rs2,40($ctx)
	lw	$rs3,44($ctx)

	slli	$len,$len,4
	add	$len,$len,$inp		# end of buffer

.Loop:
	lw	$d0,0($inp)		# load input
	lw	$d1,4($inp)
	lw	$d2,8($inp)
	lw	$d3,12($inp)
	beqz	$shr,.Laligned_inp

	lw	$t4,16($inp)
	sub	$t5,$zero,$shr
	srl	$d0,$d0,$shr
	sll	$t3,$d1,$t5
	srl	$d1,$d1,$shr
	or	$d0,$d0,$t3
	sll	$t3,$d2,$t5
	srl	$d2,$d2,$shr
	or	$d1,$d1,$t3
	sll	$t3,$d3,$t5
	srl	$d3,$d3,$shr
	or	$d2,$d2,$t3
	sll	$t4,$t4,$t5
	or	$d3,$d3,$t4

.Laligned_inp:
	srli	$t0,$h4,2		# modulo-scheduled reduction
	andi	$t1,$h4,-4
	andi	$h4,$h4,3

	add	$d0,$d0,$h0		# accumulate input
	 add	$t0,$t0,$t1
	sltu	$h0,$d0,$h0
	add	$d0,$d0,$t0		# ... and residue
	sltu	$t0,$d0,$t0

	add	$d1,$d1,$h1
	 add	$h0,$h0,$t0		# carry
	sltu	$h1,$d1,$h1
	add	$d1,$d1,$h0
	sltu	$h0,$d1,$h0

	add	$d2,$d2,$h2
	 add	$h1,$h1,$h0		# carry
	sltu	$h2,$d2,$h2
	add	$d2,$d2,$h1
	sltu	$h1,$d2,$h1

	add	$d3,$d3,$h3
	 add	$h2,$h2,$h1		# carry
	sltu	$h3,$d3,$h3
	add	$d3,$d3,$h2

	mulhu	$h1,$r0,$d0		# d0*r0
	mul	$h0,$r0,$d0

	 sltu	$h2,$d3,$h2
	 add	$h3,$h3,$h2		# carry

	mulhu	$t4,$rs3,$d1		# d1*s3
	mul	$t3,$rs3,$d1

	 add	$h4,$h4,$padbit
	 addi	$inp,$inp,16
	 add	$h4,$h4,$h3

	mulhu	$t6,$rs2,$d2		# d2*s2
	mul	$a3,$rs2,$d2
	 add	$h0,$h0,$t3
	 add	$h1,$h1,$t4
	 sltu	$t3,$h0,$t3
	 add	$h1,$h1,$t3

	mulhu	$t4,$rs1,$d3		# d3*s1
	mul	$t3,$rs1,$d3
	 add	$h0,$h0,$a3
	 add	$h1,$h1,$t6
	 sltu	$a3,$h0,$a3
	 add	$h1,$h1,$a3


	mulhu	$h2,$r1,$d0		# d0*r1
	mul	$a3,$r1,$d0
	 add	$h0,$h0,$t3
	 add	$h1,$h1,$t4
	 sltu	$t3,$h0,$t3
	 add	$h1,$h1,$t3

	mulhu	$t4,$r0,$d1		# d1*r0
	mul	$t3,$r0,$d1
	 add	$h1,$h1,$a3
	 sltu	$a3,$h1,$a3
	 add	$h2,$h2,$a3

	mulhu	$a3,$rs3,$d2		# d2*s3
	mul	$t6,$rs3,$d2
	 add	$h1,$h1,$t3
	 add	$h2,$h2,$t4
	 sltu	$t3,$h1,$t3
	 add	$h2,$h2,$t3

	mulhu	$t4,$rs2,$d3		# d3*s2
	mul	$t3,$rs2,$d3
	 add	$h1,$h1,$a3
	 add	$h2,$h2,$t6
	 sltu	$a3,$h1,$a3
	 add	$h2,$h2,$a3

	mul	$a3,$rs1,$h4		# h4*s1
	 add	$h1,$h1,$t3
	 add	$h2,$h2,$t4
	 sltu	$t3,$h1,$t3
	 add	$h2,$h2,$t3


	mulhu	$h3,$r2,$d0		# d0*r2
	mul	$t3,$r2,$d0
	 add	$h1,$h1,$a3
	 sltu	$a3,$h1,$a3
	 add	$h2,$h2,$a3

	mulhu	$t6,$r1,$d1		# d1*r1
	mul	$a3,$r1,$d1
	 add	$h2,$h2,$t3
	 sltu	$t3,$h2,$t3
	 add	$h3,$h3,$t3

	mulhu	$t4,$r0,$d2		# d2*r0
	mul	$t3,$r0,$d2
	 add	$h2,$h2,$a3
	 add	$h3,$h3,$t6
	 sltu	$a3,$h2,$a3
	 add	$h3,$h3,$a3

	mulhu	$t6,$rs3,$d3		# d3*s3
	mul	$a3,$rs3,$d3
	 add	$h2,$h2,$t3
	 add	$h3,$h3,$t4
	 sltu	$t3,$h2,$t3
	 add	$h3,$h3,$t3

	mul	$t3,$rs2,$h4		# h4*s2
	 add	$h2,$h2,$a3
	 add	$h3,$h3,$t6
	 sltu	$a3,$h2,$a3
	 add	$h3,$h3,$a3


	mulhu	$t6,$r3,$d0		# d0*r3
	mul	$a3,$r3,$d0
	 add	$h2,$h2,$t3
	 sltu	$t3,$h2,$t3
	 add	$h3,$h3,$t3

	mulhu	$t4,$r2,$d1		# d1*r2
	mul	$t3,$r2,$d1
	 add	$h3,$h3,$a3
	 sltu	$a3,$h3,$a3
	 add	$t6,$t6,$a3

	mulhu	$a3,$r0,$d3		# d3*r0
	mul	$d3,$r0,$d3
	 add	$h3,$h3,$t3
	 add	$t6,$t6,$t4
	 sltu	$t3,$h3,$t3
	 add	$t6,$t6,$t3

	mulhu	$t4,$r1,$d2		# d2*r1
	mul	$t3,$r1,$d2
	 add	$h3,$h3,$d3
	 add	$t6,$t6,$a3
	 sltu	$d3,$h3,$d3
	 add	$t6,$t6,$d3

	mul	$a3,$rs3,$h4		# h4*s3
	 add	$h3,$h3,$t3
	 add	$t6,$t6,$t4
	 sltu	$t3,$h3,$t3
	 add	$t6,$t6,$t3


	mul	$h4,$r0,$h4		# h4*r0
	 add	$h3,$h3,$a3
	 sltu	$a3,$h3,$a3
	 add	$t6,$t6,$a3
	add	$h4,$t6,$h4

	li	$padbit,1		# if we loop, padbit is 1

	bne	$inp,$len,.Loop

	sw	$h0,0($ctx)		# store hash value
	sw	$h1,4($ctx)
	sw	$h2,8($ctx)
	sw	$h3,12($ctx)
	sw	$h4,16($ctx)

	lw	$ra, 4*11($sp)
	lw	$s0, 4*10($sp)
	lw	$s1, 4*9($sp)
	lw	$s2, 4*8($sp)
	lw	$s3, 4*7($sp)
	lw	$s4, 4*6($sp)
	lw	$s5, 4*5($sp)
	lw	$s6, 4*4($sp)
	lw	$s7, 4*3($sp)
	addi	$sp,$sp,4*12
.Labort:
	ret
.size	poly1305_blocks,.-poly1305_blocks
___
}
{
my ($ctx,$mac,$nonce,$tmp4) = ($a0,$a1,$a2,$a3);

$code.=<<___;
.globl	poly1305_emit
.type	poly1305_emit,\@function
poly1305_emit:
	lw	$tmp4,16($ctx)
	lw	$tmp0,0($ctx)
	lw	$tmp1,4($ctx)
	lw	$tmp2,8($ctx)
	lw	$tmp3,12($ctx)

	srl	$ctx,$tmp4,2		# final reduction
	andi	$in0,$tmp4,4
	andi	$tmp4,$tmp4,3
	add	$ctx,$ctx,$in0

	add	$tmp0,$tmp0,$ctx
	sltu	$ctx,$tmp0,$ctx
	 addi	$in0,$tmp0,5		# compare to modulus
	add	$tmp1,$tmp1,$ctx
	 sltiu	$in1,$in0,5
	sltu	$ctx,$tmp1,$ctx
	 add	$in1,$in1,$tmp1
	add	$tmp2,$tmp2,$ctx
	 sltu	$in2,$in1,$tmp1
	sltu	$ctx,$tmp2,$ctx
	 add	$in2,$in2,$tmp2
	add	$tmp3,$tmp3,$ctx
	 sltu	$in3,$in2,$tmp2
	sltu	$ctx,$tmp3,$ctx
	 add	$in3,$in3,$tmp3
	add	$tmp4,$tmp4,$ctx
	 sltu	$ctx,$in3,$tmp3
	 add	$ctx,$ctx,$tmp4

	srl	$ctx,$ctx,2		# see if it carried/borrowed
	sub	$ctx,$zero,$ctx

	xor	$in0,$in0,$tmp0
	xor	$in1,$in1,$tmp1
	xor	$in2,$in2,$tmp2
	xor	$in3,$in3,$tmp3
	and	$in0,$in0,$ctx
	and	$in1,$in1,$ctx
	and	$in2,$in2,$ctx
	and	$in3,$in3,$ctx
	xor	$in0,$in0,$tmp0
	xor	$in1,$in1,$tmp1
	xor	$in2,$in2,$tmp2
	xor	$in3,$in3,$tmp3

	lw	$tmp0,0($nonce)		# load nonce
	lw	$tmp1,4($nonce)
	lw	$tmp2,8($nonce)
	lw	$tmp3,12($nonce)

	add	$in0,$in0,$tmp0		# accumulate nonce
	sltu	$ctx,$in0,$tmp0

	add	$in1,$in1,$tmp1
	sltu	$tmp1,$in1,$tmp1
	add	$in1,$in1,$ctx
	sltu	$ctx,$in1,$ctx
	add	$ctx,$ctx,$tmp1

	add	$in2,$in2,$tmp2
	sltu	$tmp2,$in2,$tmp2
	add	$in2,$in2,$ctx
	sltu	$ctx,$in2,$ctx
	add	$ctx,$ctx,$tmp2

	add	$in3,$in3,$tmp3
	add	$in3,$in3,$ctx

	srl	$tmp0,$in0,8		# write mac value
	srl	$tmp1,$in0,16
	srl	$tmp2,$in0,24
	sb	$in0, 0($mac)
	sb	$tmp0,1($mac)
	srl	$tmp0,$in1,8
	sb	$tmp1,2($mac)
	srl	$tmp1,$in1,16
	sb	$tmp2,3($mac)
	srl	$tmp2,$in1,24
	sb	$in1, 4($mac)
	sb	$tmp0,5($mac)
	srl	$tmp0,$in2,8
	sb	$tmp1,6($mac)
	srl	$tmp1,$in2,16
	sb	$tmp2,7($mac)
	srl	$tmp2,$in2,24
	sb	$in2, 8($mac)
	sb	$tmp0,9($mac)
	srl	$tmp0,$in3,8
	sb	$tmp1,10($mac)
	srl	$tmp1,$in3,16
	sb	$tmp2,11($mac)
	srl	$tmp2,$in3,24
	sb	$in3, 12($mac)
	sb	$tmp0,13($mac)
	sb	$tmp1,14($mac)
	sb	$tmp2,15($mac)

	ret
.size	poly1305_emit,.-poly1305_emit
.string	"Poly1305 for RISC-V, CRYPTOGAMS by \@dot-asm"
___
}
}}}

print $code;
close STDOUT;


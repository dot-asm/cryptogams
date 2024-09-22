#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use with OpenSSL.
# ====================================================================
#
# Keccak-1600 for Oracle SPARC Architecture 2017.
#
# September 2024.
#
# SPARC M8 spends 1.45 cycles per byte processed with SHA3-256.
# Multi-process benchmark saturates at 32x single-process result,
# or almost 115GBps for a 5GHz socket.
#
########################################################################

my ($A_flat,$inp,$len,$bsz) = map("%o$_",(0..3));

$code.=<<___;
#if defined(__SUNPRO_C) && defined(__sparcv9) && !defined(__arch64__)
# define __arch64__
#endif

#if defined(__arch64__)
# define SIZE_T_CC	%xcc
#else
# define SIZE_T_CC	%icc
#endif

.section        ".text",#alloc,#execinstr

.globl	SHA3_absorb
.type	SHA3_absorb, #function
.align	32
SHA3_absorb:
	subcc		$len, $bsz, $len
	bcs,pn		SIZE_T_CC, .Labsorb_nothing_to_do
	andcc		$inp, 0x7, %g0

	rd		%asi, %o4		! save %asi
	wr		%g0, 0x88, %asi		! ASI_PRIMARY_LITTLE
	alignaddrl	$inp, %g0, $inp

	ldd		[$A_flat + 8*0], %f48	! load A[5][5]
	ldd		[$A_flat + 8*1], %f46
	ldd		[$A_flat + 8*2], %f44
	ldd		[$A_flat + 8*3], %f42
	ldd		[$A_flat + 8*4], %f40

	ldd		[$A_flat + 8*5], %f38
	ldd		[$A_flat + 8*6], %f36
	ldd		[$A_flat + 8*7], %f34
	ldd		[$A_flat + 8*8], %f32
	ldd		[$A_flat + 8*9], %f30

	ldd		[$A_flat + 8*10], %f28
	ldd		[$A_flat + 8*11], %f26
	ldd		[$A_flat + 8*12], %f24
	ldd		[$A_flat + 8*13], %f22
	ldd		[$A_flat + 8*14], %f20

	ldd		[$A_flat + 8*15], %f18
	ldd		[$A_flat + 8*16], %f16
	ldd		[$A_flat + 8*17], %f14
	ldd		[$A_flat + 8*18], %f12
	ldd		[$A_flat + 8*19], %f10

	ldd		[$A_flat + 8*20], %f8
	ldd		[$A_flat + 8*21], %f6
	ldd		[$A_flat + 8*22], %f4
	ldd		[$A_flat + 8*23], %f2
	ldd		[$A_flat + 8*24], %f0

	bz,pt		%icc, .Loop_aligned
	nop

	ldda		[$inp + 8*0]%asi, %f60
.Loop_unaligned:
	ldda		[$inp + 8*1]%asi, %f56
	ldda		[$inp + 8*2]%asi, %f54
	ldda		[$inp + 8*3]%asi, %f52
	ldda		[$inp + 8*4]%asi, %f50
	cmp		$bsz, (1600-384*2)/8	! SHA3-512 or SHA3-384
	ldda		[$inp + 8*5]%asi, %f62

	faligndata	%f56, %f60, %f58
	faligndata	%f54, %f56, %f56
	faligndata	%f52, %f54, %f54
	faligndata	%f50, %f52, %f52
	faligndata	%f62, %f50, %f50

	fxord		%f58, %f48, %f48
	fxord		%f56, %f46, %f46
	ldda		[$inp + 8*6]%asi, %f56
	fxord		%f54, %f44, %f44
	ldda		[$inp + 8*7]%asi, %f54
	fxord		%f52, %f42, %f42
	ldda		[$inp + 8*8]%asi, %f52
	fxord		%f50, %f40, %f40
	ldda		[$inp + 8*9]%asi, %f60

	faligndata	%f56, %f62, %f58
	faligndata	%f54, %f56, %f56
	faligndata	%f52, %f54, %f54
	faligndata	%f60, %f52, %f52

	fxord		%f58, %f38, %f38
	fxord		%f56, %f36, %f36
	fxord		%f54, %f34, %f34
	blu,pn		%icc, .Ldo_unaligned
	fxord		%f52, %f32, %f32	! SHA3-512

	ldda		[$inp + 8*10]%asi, %f58
	ldda		[$inp + 8*11]%asi, %f56
	ldda		[$inp + 8*12]%asi, %f54
	faligndata	%f58, %f60, %f50
	ldda		[$inp + 8*13]%asi, %f60

	faligndata	%f56, %f58, %f58
	faligndata	%f54, %f56, %f56
	faligndata	%f60, %f54, %f54

	fxord		%f50, %f30, %f30
	fxord		%f58, %f28, %f28
	fxord		%f56, %f26, %f26
	beq,pn		%icc, .Ldo_unaligned
	fxord		%f54, %f24, %f24	! SHA3-384

	ldda		[$inp + 8*14]%asi, %f50
	ldda		[$inp + 8*15]%asi, %f58
	cmp		$bsz, (1600-224*2)/8	! SHA3-256 or SHA3-224
	ldda		[$inp + 8*16]%asi, %f56
	faligndata	%f50, %f60, %f52
	ldda		[$inp + 8*17]%asi, %f60

	faligndata	%f58, %f50, %f50
	faligndata	%f56, %f58, %f58
	faligndata	%f60, %f56, %f56

	fxord		%f52, %f22, %f22
	fxord		%f50, %f20, %f20
	fxord		%f58, %f18, %f18
	blu,pn		%icc, .Ldo_unaligned
	fxord		%f56, %f16, %f16	! SHA3-256

	ldda		[$inp + 8*18]%asi, %f52
	faligndata	%f52, %f60, %f54
	fmovd		%f52, %f60
	beq,pn		%icc, .Ldo_unaligned
	fxord		%f54, %f14, %f14	! SHA3-224

	ldda		[$inp + 8*19]%asi, %f50
	ldda		[$inp + 8*20]%asi, %f58
	ldda		[$inp + 8*21]%asi, %f60

	faligndata	%f50, %f52, %f52
	faligndata	%f58, %f50, %f50
	faligndata	%f60, %f58, %f58

	fxord		%f52, %f12, %f12
	fxord		%f50, %f10, %f10
	fxord		%f58, %f8, %f8

.Ldo_unaligned:
	add		$inp, $bsz, $inp	! advance inp
	subcc		$len, $bsz, $len

	.word		0x81b02880		! SHA3

	bcc		SIZE_T_CC, .Loop_unaligned
	nop

	ba		.Ldone_absorb
	nop

.align	32
.Loop_aligned:
	ldda		[$inp + 8*0]%asi, %f58
	ldda		[$inp + 8*1]%asi, %f56
	ldda		[$inp + 8*2]%asi, %f54
	ldda		[$inp + 8*3]%asi, %f52
	cmp		$bsz, (1600-384*2)/8	! SHA3-512 or SHA3-384
	ldda		[$inp + 8*4]%asi, %f50
	fxord		%f58, %f48, %f48
	ldda		[$inp + 8*5]%asi, %f58
	fxord		%f56, %f46, %f46
	ldda		[$inp + 8*6]%asi, %f56
	fxord		%f54, %f44, %f44
	ldda		[$inp + 8*7]%asi, %f54
	fxord		%f52, %f42, %f42
	ldda		[$inp + 8*8]%asi, %f52
	fxord		%f50, %f40, %f40
	fxord		%f58, %f38, %f38
	fxord		%f56, %f36, %f36
	fxord		%f54, %f34, %f34
	blu,pn		%icc, .Ldo_aligned
	fxord		%f52, %f32, %f32	! SHA3-512

	ldda		[$inp + 8*9]%asi,  %f50
	ldda		[$inp + 8*10]%asi, %f58
	ldda		[$inp + 8*11]%asi, %f56
	ldda		[$inp + 8*12]%asi, %f54
	fxord		%f50, %f30, %f30
	fxord		%f58, %f28, %f28
	fxord		%f56, %f26, %f26
	beq,pn		%icc, .Ldo_aligned
	fxord		%f54, %f24, %f24	! SHA3-384

	ldda		[$inp + 8*13]%asi, %f52
	ldda		[$inp + 8*14]%asi, %f50
	ldda		[$inp + 8*15]%asi, %f58
	cmp		$bsz, (1600-224*2)/8	! SHA3-256 or SHA3-224
	ldda		[$inp + 8*16]%asi, %f56
	fxord		%f52, %f22, %f22
	fxord		%f50, %f20, %f20
	fxord		%f58, %f18, %f18
	blu,pn		%icc, .Ldo_aligned
	fxord		%f56, %f16, %f16	! SHA3-256

	ldda		[$inp + 8*17]%asi, %f54
	beq,pn		%icc, .Ldo_aligned
	fxord		%f54, %f14, %f14	! SHA3-224

	ldda		[$inp + 8*18]%asi, %f52
	ldda		[$inp + 8*19]%asi, %f50
	ldda		[$inp + 8*20]%asi, %f58
	fxord		%f52, %f12, %f12
	fxord		%f50, %f10, %f10
	fxord		%f58, %f8, %f8

.Ldo_aligned:
	add		$inp, $bsz, $inp	! advance inp
	subcc		$len, $bsz, $len

	.word		0x81b02880		! SHA3

	bcc		SIZE_T_CC, .Loop_aligned
	nop

.Ldone_absorb:
	wr		%g0, %o4, %asi		! restore %asi

	std		%f48, [$A_flat + 8*0]	! store A[5][5]
	std		%f46, [$A_flat + 8*1]
	std		%f44, [$A_flat + 8*2]
	std		%f42, [$A_flat + 8*3]
	std		%f40, [$A_flat + 8*4]

	std		%f38, [$A_flat + 8*5]
	std		%f36, [$A_flat + 8*6]
	std		%f34, [$A_flat + 8*7]
	std		%f32, [$A_flat + 8*8]
	std		%f30, [$A_flat + 8*9]

	std		%f28, [$A_flat + 8*10]
	std		%f26, [$A_flat + 8*11]
	std		%f24, [$A_flat + 8*12]
	std		%f22, [$A_flat + 8*13]
	std		%f20, [$A_flat + 8*14]

	std		%f18, [$A_flat + 8*15]
	std		%f16, [$A_flat + 8*16]
	std		%f14, [$A_flat + 8*17]
	std		%f12, [$A_flat + 8*18]
	std		%f10, [$A_flat + 8*19]

	std		%f8, [$A_flat + 8*20]
	std		%f6, [$A_flat + 8*21]
	std		%f4, [$A_flat + 8*22]
	std		%f2, [$A_flat + 8*23]
	std		%f0, [$A_flat + 8*24]

.Labsorb_nothing_to_do:
	retl
	add		$len, $bsz, %o0		! return value
.size	SHA3_absorb, .-SHA3_absorb
___

$out=$inp;

$code.=<<___;
.globl	SHA3_squeeze
.type	SHA3_squeeze, #function
.align	32
SHA3_squeeze:
	mov		$A_flat, %o4
	srl		$bsz, 3, %o5
	nop
	nop

.Loop_squeeze:
	cmp		$len, 8
	ldx		[%o4], %g1
	blu,pn		SIZE_T_CC, .Ltail_squeeze
	add		%o4, 8, %o4

	stb		%g1, [$out + 0]
	srlx		%g1, 8, %g1
	stb		%g1, [$out + 1]
	srlx		%g1, 8, %g1
	stb		%g1, [$out + 2]
	srlx		%g1, 8, %g1
	stb		%g1, [$out + 3]
	srlx		%g1, 8, %g1
	stb		%g1, [$out + 4]
	srlx		%g1, 8, %g1
	stb		%g1, [$out + 5]
	srlx		%g1, 8, %g1
	stb		%g1, [$out + 6]
	srlx		%g1, 8, %g1
	stb		%g1, [$out + 7]
	sub		$len, 8, $len
	add		$out, 8, $out
	brz		$len, .Ldone_squeeze
	sub		%o5, 1, %o5

	brnz		%o5, .Loop_squeeze
	nop

	ldd		[$A_flat + 8*0], %f48	! load A[5][5]
	ldd		[$A_flat + 8*1], %f46
	ldd		[$A_flat + 8*2], %f44
	ldd		[$A_flat + 8*3], %f42
	ldd		[$A_flat + 8*4], %f40

	ldd		[$A_flat + 8*5], %f38
	ldd		[$A_flat + 8*6], %f36
	ldd		[$A_flat + 8*7], %f34
	ldd		[$A_flat + 8*8], %f32
	ldd		[$A_flat + 8*9], %f30

	ldd		[$A_flat + 8*10], %f28
	ldd		[$A_flat + 8*11], %f26
	ldd		[$A_flat + 8*12], %f24
	ldd		[$A_flat + 8*13], %f22
	ldd		[$A_flat + 8*14], %f20

	ldd		[$A_flat + 8*15], %f18
	ldd		[$A_flat + 8*16], %f16
	ldd		[$A_flat + 8*17], %f14
	ldd		[$A_flat + 8*18], %f12
	ldd		[$A_flat + 8*19], %f10

	ldd		[$A_flat + 8*20], %f8
	ldd		[$A_flat + 8*21], %f6
	ldd		[$A_flat + 8*22], %f4
	ldd		[$A_flat + 8*23], %f2
	ldd		[$A_flat + 8*24], %f0

	.word		0x81b02880		! SHA3

	std		%f48, [$A_flat + 8*0]	! store A[5][5]
	std		%f46, [$A_flat + 8*1]
	std		%f44, [$A_flat + 8*2]
	std		%f42, [$A_flat + 8*3]
	std		%f40, [$A_flat + 8*4]

	std		%f38, [$A_flat + 8*5]
	std		%f36, [$A_flat + 8*6]
	std		%f34, [$A_flat + 8*7]
	std		%f32, [$A_flat + 8*8]
	std		%f30, [$A_flat + 8*9]

	std		%f28, [$A_flat + 8*10]
	std		%f26, [$A_flat + 8*11]
	std		%f24, [$A_flat + 8*12]
	std		%f22, [$A_flat + 8*13]
	std		%f20, [$A_flat + 8*14]

	std		%f18, [$A_flat + 8*15]
	std		%f16, [$A_flat + 8*16]
	std		%f14, [$A_flat + 8*17]
	std		%f12, [$A_flat + 8*18]
	std		%f10, [$A_flat + 8*19]

	std		%f8, [$A_flat + 8*20]
	std		%f6, [$A_flat + 8*21]
	std		%f4, [$A_flat + 8*22]
	std		%f2, [$A_flat + 8*23]
	std		%f0, [$A_flat + 8*24]

	mov		$A_flat, %o4
	ba		.Loop_squeeze
	srl		$bsz, 3, %o5

.align	16
.Ltail_squeeze:
	stb		%g1, [$out]
	sub		$len, 1, $len
	add		$out, 1, $out
	brnz		$len, .Ltail_squeeze
	srlx		%g1, 8, %g1

.Ldone_squeeze:
	retl
	nop
.size	SHA3_squeeze, .-SHA3_squeeze

.asciz	"Keccak-1600 absorb and squeeze for SPARC 2017, CRYPTOGAMS by \@dot-asm"
___

print $code;

close STDOUT;

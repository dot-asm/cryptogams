#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for use with OpenSSL.
# ====================================================================
#
# Keccak-1600 for x86_64 APX ISA extension.
#
# August 2024.
#
# This is straightforward KECCAK_1X_ALT implementation with A[][]
# held in registers.
#
########################################################################

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;

my @A = map([ "%r$_", "%r".($_+1), "%r".($_+2), "%r".($_+3), "%r".($_+4) ],
            (7, 12, 17, 22, 27));
   $A[0][0] = "%rbp";	# there is no %r7

my @C = ("%rax","%rbx","%rcx","%rdx","%rdi","%rsi");
my ($A_flat, $iotas) = ("%rdi", "%rsi");

my @rhotates = ([  0,  1, 62, 28, 27 ],
                [ 36, 44,  6, 55, 20 ],
                [  3, 10, 43, 25, 39 ],
                [ 41, 45, 15, 21,  8 ],
                [ 18,  2, 61, 56, 14 ]);

$code.=<<___;
.text

.type	__KeccakF1600,\@abi-omnipotent
.align	32
__KeccakF1600:
.cfi_startproc
	sub	\$8,%rsp
.cfi_alloca	8
.cfi_end_prologue
	lea	iotas(%rip),$iotas
	jmp	.Loop

.align	32
.Loop:
	######################################### Theta
	xor	$A[0][0],$A[1][0],$C[0]
	xor	$A[0][1],$A[1][1],$C[1]
	xor	$A[0][2],$A[1][2],$C[2]
	xor	$A[0][3],$A[1][3],$C[3]
	xor	$A[0][4],$A[1][4],$C[4]
	 mov	$iotas,(%rsp)			# offload $iotas
	xor	$A[2][0],$C[0]
	xor	$A[2][1],$C[1]
	xor	$A[2][2],$C[2]
	xor	$A[2][3],$C[3]
	xor	$A[2][4],$C[4]

	xor	$A[3][0],$C[0]
	xor	$A[3][1],$C[1]
	xor	$A[3][2],$C[2]
	xor	$A[3][3],$C[3]
	xor	$A[3][4],$C[4]

	xor	$A[4][0],$C[0]
	xor	$A[4][2],$C[2]
	xor	$A[4][1],$C[1]
	xor	$A[4][3],$C[3]
	xor	$A[4][4],$C[4]

	rorx	\$63,$C[2],$C[5]
	xor	$C[0],$C[5]			# eor	$C[5],$C[0],$C[2],ror#63

	xor	$C[5],$A[0][1]
	xor	$C[5],$A[1][1]
	xor	$C[5],$A[2][1]
	xor	$C[5],$A[3][1]
	xor	$C[5],$A[4][1]

	rorx	\$63,$C[3],$C[5]
	xor	$C[1],$C[5]			# eor	$C[5],$C[1],$C[3],ror#63

	xor	$C[5],$A[0][2]
	xor	$C[5],$A[1][2]
	xor	$C[5],$A[2][2]
	xor	$C[5],$A[3][2]
	xor	$C[5],$A[4][2]

	rorx	\$63,$C[4],$C[5]
	xor	$C[5],$C[2]			# eor	$C[2],$C[2],$C[4],ror#63
	ror	\$63,$C[0]
	xor	$C[0],$C[3]			# eor	$C[3],$C[3],$C[0],ror#63

	xor	$C[2],$A[0][3],$C[0] 		# mov  $C[0],$A[0][3]
	xor	$C[2],$A[1][3]
	xor	$C[2],$A[2][3]
	xor	$C[2],$A[3][3]
	xor	$C[2],$A[4][3]

	ror	\$63,$C[1]
	xor	$C[1],$C[4]			# eor	$C[4],$C[4],$C[1],ror#63

	xor	$C[3],$A[0][4],$C[2] 		# mov  $C[2],$A[0][4]
	xor	$C[3],$A[1][4]
	xor	$C[3],$A[2][4]
	xor	$C[3],$A[3][4]
	xor	$C[3],$A[4][4]

	xor	$C[4],$A[0][0]
	xor	$C[4],$A[1][0]
	xor	$C[4],$A[2][0]
	xor	$C[4],$A[3][0]
	xor	$C[4],$A[4][0]

	######################################### Rho+Pi
	mov	$A[0][1],$C[3]
	rorx	\$64-$rhotates[1][1],$A[1][1],$A[0][1]
	mov	$A[0][2],$C[1]
	rorx	\$64-$rhotates[2][2],$A[2][2],$A[0][2]
	# mov	$A[0][3],$C[0]
	rorx	\$64-$rhotates[3][3],$A[3][3],$A[0][3]
	# mov	$A[0][4],$C[2]
	rorx	\$64-$rhotates[4][4],$A[4][4],$A[0][4]

	rorx	\$64-$rhotates[1][4],$A[1][4],$A[1][1]
	rorx	\$64-$rhotates[2][3],$A[2][3],$A[2][2]
	rorx	\$64-$rhotates[3][2],$A[3][2],$A[3][3]
	rorx	\$64-$rhotates[4][1],$A[4][1],$A[4][4]

	rorx	\$64-$rhotates[4][2],$A[4][2],$A[1][4]
	rorx	\$64-$rhotates[3][4],$A[3][4],$A[2][3]
	rorx	\$64-$rhotates[2][1],$A[2][1],$A[3][2]
	rorx	\$64-$rhotates[1][3],$A[1][3],$A[4][1]

	rorx	\$64-$rhotates[2][4],$A[2][4],$A[4][2]
	rorx	\$64-$rhotates[4][3],$A[4][3],$A[3][4]
	rorx	\$64-$rhotates[1][2],$A[1][2],$A[2][1]
	rorx	\$64-$rhotates[3][1],$A[3][1],$A[1][3]

	rorx	\$64-$rhotates[4][0],$A[4][0],$A[2][4]
	rorx	\$64-$rhotates[3][0],$A[3][0],$A[4][3]
	rorx	\$64-$rhotates[2][0],$A[2][0],$A[1][2]
	rorx	\$64-$rhotates[1][0],$A[1][0],$A[3][1]

	rorx	\$64-$rhotates[0][3],$C[0],$A[1][0]
	rorx	\$64-$rhotates[0][1],$C[3],$A[2][0]
	rorx	\$64-$rhotates[0][4],$C[2],$A[3][0]
	rorx	\$64-$rhotates[0][2],$C[1],$A[4][0]

	######################################### Chi+Iota
	andn	$A[0][2],$A[0][1],$C[0] 
	andn	$A[0][3],$A[0][2],$C[1] 
	andn	$A[0][0],$A[0][4],$C[2] 
	andn	$A[0][1],$A[0][0],$C[3] 
	andn	$A[0][4],$A[0][3],$C[4]
	 mov	(%rsp),$iotas
	xor	$C[0],$A[0][0]
	xor	$C[1],$A[0][1]
	xor	$C[2],$A[0][3]
	xor	$C[3],$A[0][4]
	xor	$C[4],$A[0][2]
	 xor	($iotas),$A[0][0]		# A[0][0] ^= Iota[i++]
	 lea	8($iotas),$iotas

	andn	$A[1][2],$A[1][1],$C[0]
	andn	$A[1][3],$A[1][2],$C[1]
	andn	$A[1][0],$A[1][4],$C[2]
	andn	$A[1][1],$A[1][0],$C[3]
	andn	$A[1][4],$A[1][3],$C[4]
	xor	$C[0],$A[1][0]
	xor	$C[1],$A[1][1]
	xor	$C[2],$A[1][3]
	xor	$C[3],$A[1][4]
	xor	$C[4],$A[1][2]

	andn	$A[2][2],$A[2][1],$C[0]
	andn	$A[2][3],$A[2][2],$C[1]
	andn	$A[2][0],$A[2][4],$C[2]
	andn	$A[2][1],$A[2][0],$C[3]
	andn	$A[2][4],$A[2][3],$C[4]
	xor	$C[0],$A[2][0]
	xor	$C[1],$A[2][1]
	xor	$C[2],$A[2][3]
	xor	$C[3],$A[2][4]
	xor	$C[4],$A[2][2]

	andn	$A[3][2],$A[3][1],$C[0]
	andn	$A[3][3],$A[3][2],$C[1]
	andn	$A[3][0],$A[3][4],$C[2]
	andn	$A[3][1],$A[3][0],$C[3]
	andn	$A[3][4],$A[3][3],$C[4]
	xor	$C[0],$A[3][0]
	xor	$C[1],$A[3][1]
	xor	$C[2],$A[3][3]
	xor	$C[3],$A[3][4]
	xor	$C[4],$A[3][2]

	andn	$A[4][2],$A[4][1],$C[0]
	andn	$A[4][3],$A[4][2],$C[1]
	andn	$A[4][0],$A[4][4],$C[2]
	andn	$A[4][1],$A[4][0],$C[3]
	andn	$A[4][4],$A[4][3],$C[4]
	xor	$C[0],$A[4][0]
	xor	$C[1],$A[4][1]
	xor	$C[2],$A[4][3]
	xor	$C[3],$A[4][4]
	xor	$C[4],$A[4][2]

	test	\$255,$iotas
	jne	.Loop

	add	\$8,%rsp
.cfi_alloca	-8
.cfi_epilogue
	ret
.cfi_endproc
.size	__KeccakF1600,.-__KeccakF1600

.globl	KeccakF1600
.type	KeccakF1600,\@function,1,"unwind"
.align	32
KeccakF1600:
.cfi_startproc
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	sub	\$8,%rsp
.cfi_alloca	8
.cfi_end_prologue

	mov	8*0($A_flat),$A[0][0]
	mov	8*1($A_flat),$A[0][1]
	mov	8*2($A_flat),$A[0][2]
	mov	8*3($A_flat),$A[0][3]
	mov	8*4($A_flat),$A[0][4]

	mov	8*5($A_flat),$A[1][0]
	mov	8*6($A_flat),$A[1][1]
	mov	8*7($A_flat),$A[1][2]
	mov	8*8($A_flat),$A[1][3]
	mov	8*9($A_flat),$A[1][4]
	lea	8*15($A_flat),$C[0]		# size optimization

	mov	8*10($A_flat),$A[2][0]
	mov	8*11($A_flat),$A[2][1]
	mov	8*12($A_flat),$A[2][2]
	mov	8*13($A_flat),$A[2][3]
	mov	8*14($A_flat),$A[2][4]

	mov	8*0($C[0]),$A[3][0]
	mov	8*1($C[0]),$A[3][1]
	mov	8*2($C[0]),$A[3][2]
	mov	8*3($C[0]),$A[3][3]
	mov	8*4($C[0]),$A[3][4]

	mov	8*5($C[0]),$A[4][0]
	mov	8*6($C[0]),$A[4][1]
	mov	8*7($C[0]),$A[4][2]
	mov	8*8($C[0]),$A[4][3]
	mov	8*9($C[0]),$A[4][4]

	mov	$A_flat,(%rsp)
	call	__KeccakF1600
	mov	(%rsp),$A_flat

	mov	$A[0][0],8*0($A_flat)
	mov	$A[0][1],8*1($A_flat)
	mov	$A[0][2],8*2($A_flat)
	mov	$A[0][3],8*3($A_flat)
	mov	$A[0][4],8*4($A_flat)

	mov	$A[1][0],8*5($A_flat)
	mov	$A[1][1],8*6($A_flat)
	mov	$A[1][2],8*7($A_flat)
	mov	$A[1][3],8*8($A_flat)
	mov	$A[1][4],8*9($A_flat)
	lea	8*15($A_flat),$C[0]		# size optimization

	mov	$A[2][0],8*10($A_flat)
	mov	$A[2][1],8*11($A_flat)
	mov	$A[2][2],8*12($A_flat)
	mov	$A[2][3],8*13($A_flat)
	mov	$A[2][4],8*14($A_flat)

	mov	$A[3][0],8*0($C[0])
	mov	$A[3][1],8*1($C[0])
	mov	$A[3][2],8*2($C[0])
	mov	$A[3][3],8*3($C[0])
	mov	$A[3][4],8*4($C[0])

	mov	$A[4][0],8*5($C[0])
	mov	$A[4][1],8*6($C[0])
	mov	$A[4][2],8*7($C[0])
	mov	$A[4][3],8*8($C[0])
	mov	$A[4][4],8*9($C[0])

	lea	56(%rsp),%r11
.cfi_def_cfa	%r11,8
	mov	-48(%r11),%r15
	mov	-40(%r11),%r14
	mov	-32(%r11),%r13
	mov	-24(%r11),%r12
	mov	-16(%r11),%rbp
	mov	-8(%r11),%rbx
	lea	(%r11),%rsp
.cfi_epilogue
	ret
.cfi_endproc
.size	KeccakF1600,.-KeccakF1600
___

{ my ($A_flat,$inp,$len,$bsz) = ("%rdi","%rsi","%rdx","%rcx");

$code.=<<___;
.globl	SHA3_absorb
.type	SHA3_absorb,\@function,4,"unwind"
.align	32
SHA3_absorb:
.cfi_startproc
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	sub	\$40,%rsp
.cfi_alloca	40
.cfi_end_prologue

	mov	8*0($A_flat),$A[0][0]
	mov	8*1($A_flat),$A[0][1]
	mov	8*2($A_flat),$A[0][2]
	mov	8*3($A_flat),$A[0][3]
	mov	8*4($A_flat),$A[0][4]

	mov	8*5($A_flat),$A[1][0]
	mov	8*6($A_flat),$A[1][1]
	mov	8*7($A_flat),$A[1][2]
	mov	8*8($A_flat),$A[1][3]
	mov	8*9($A_flat),$A[1][4]
	lea	8*15($A_flat),$C[0]		# size optimization

	mov	8*10($A_flat),$A[2][0]
	mov	8*11($A_flat),$A[2][1]
	mov	8*12($A_flat),$A[2][2]
	mov	8*13($A_flat),$A[2][3]
	mov	8*14($A_flat),$A[2][4]

	mov	8*0($C[0]),$A[3][0]
	mov	8*1($C[0]),$A[3][1]
	mov	8*2($C[0]),$A[3][2]
	mov	8*3($C[0]),$A[3][3]
	mov	8*4($C[0]),$A[3][4]

	mov	8*5($C[0]),$A[4][0]
	mov	8*6($C[0]),$A[4][1]
	mov	8*7($C[0]),$A[4][2]
	mov	8*8($C[0]),$A[4][3]
	mov	8*9($C[0]),$A[4][4]

	mov	$A_flat,24(%rsp)		# save A_flat

.Loop_absorb:
	sub	$bsz,$len
	jc	.Ldone_absorb
___
sub load_n_xor {
    my ($from,$to) = @_;
    my $ptr = $from<13 ? $inp : $C[0];

    for (my $i=$from; $i<=$to; $i++) {
        my $off = 8*$i;
	$off -= 13*8 if ($from>=13);
$code.=<<___;
	xor	$off($ptr),$A[$i/5][$i%5]
___
    }
    my $_bsz=++$to*8;
$code.=<<___ if ($to<20);
	cmp	\$$_bsz,$bsz
	je	.Lprocess_block
___
$code.=<<___ if ($to==9);
	lea	13*8($inp),$C[0]		# size optimization
___
}
load_n_xor(0,8);
load_n_xor(9,12);
load_n_xor(13,16);
load_n_xor(17,17);
load_n_xor(18,20);
$code.=<<___;
.Lprocess_block:
	lea	($inp,$bsz),$inp

	mov	$bsz,0(%rsp)			# save bsz
	mov	$len,8(%rsp)			# save len
	mov	$inp,16(%rsp)			# save inp
	call	__KeccakF1600
	mov	0(%rsp),$bsz			# pull bsz
	mov	8(%rsp),$len			# pull len
	mov	16(%rsp),$inp			# pull inp
	mov	24(%rsp),$A_flat
	jmp	.Loop_absorb

.align	32
.Ldone_absorb:
	mov	$A[0][0],8*0($A_flat)
	mov	$A[0][1],8*1($A_flat)
	mov	$A[0][2],8*2($A_flat)
	mov	$A[0][3],8*3($A_flat)
	mov	$A[0][4],8*4($A_flat)

	mov	$A[1][0],8*5($A_flat)
	mov	$A[1][1],8*6($A_flat)
	mov	$A[1][2],8*7($A_flat)
	mov	$A[1][3],8*8($A_flat)
	mov	$A[1][4],8*9($A_flat)
	lea	8*15($A_flat),$C[0]		# size optimization

	mov	$A[2][0],8*10($A_flat)
	mov	$A[2][1],8*11($A_flat)
	mov	$A[2][2],8*12($A_flat)
	mov	$A[2][3],8*13($A_flat)
	mov	$A[2][4],8*14($A_flat)

	mov	$A[3][0],8*0($C[0])
	mov	$A[3][1],8*1($C[0])
	mov	$A[3][2],8*2($C[0])
	mov	$A[3][3],8*3($C[0])
	mov	$A[3][4],8*4($C[0])

	mov	$A[4][0],8*5($C[0])
	mov	$A[4][1],8*6($C[0])
	mov	$A[4][2],8*7($C[0])
	mov	$A[4][3],8*8($C[0])
	mov	$A[4][4],8*9($C[0])

	lea	($len,$bsz),%rax		# return value

	lea	88(%rsp),%r11
.cfi_def_cfa	%r11,8
	mov	-48(%r11),%r15
	mov	-40(%r11),%r14
	mov	-32(%r11),%r13
	mov	-24(%r11),%r12
	mov	-16(%r11),%rbp
	mov	-8(%r11),%rbx
	lea	(%r11),%rsp
.cfi_epilogue
	ret
.cfi_endproc
.size	SHA3_absorb,.-SHA3_absorb
___
}
{ my ($A_flat,$out,$len,$bsz) = ("%rdi","%rsi","%rdx","%rcx");
     ($out,$len,$bsz) = ("%r12","%r13","%r14");

$code.=<<___;
.globl	SHA3_squeeze
.type	SHA3_squeeze,\@function,4,"unwind"
.align	32
SHA3_squeeze:
.cfi_startproc
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	sub	\$32,%rsp			# Windows thing
.cfi_alloca	32
.cfi_end_prologue

	shr	\$3,%rcx
	mov	$A_flat,%r8
	mov	%rsi,$out
	mov	%rdx,$len
	mov	%rcx,$bsz
	jmp	.Loop_squeeze

.align	32
.Loop_squeeze:
	cmp	\$8,$len
	jb	.Ltail_squeeze

	mov	(%r8),%rax
	lea	8(%r8),%r8
	mov	%rax,($out)
	lea	8($out),$out
	sub	\$8,$len			# len -= 8
	jz	.Ldone_squeeze

	sub	\$1,%rcx			# bsz--
	jnz	.Loop_squeeze

	mov	%rdi,%rcx			# Windows thing
	call	KeccakF1600
	mov	$A_flat,%r8
	mov	$bsz,%rcx
	jmp	.Loop_squeeze

.Ltail_squeeze:
	mov	%r8, %rsi
	mov	$out,%rdi
	mov	$len,%rcx
	.byte	0xf3,0xa4			# rep	movsb

.Ldone_squeeze:
	mov	32(%rsp),%r14
	mov	40(%rsp),%r13
	mov	48(%rsp),%r12
	add	\$56,%rsp
.cfi_alloca	-56
.cfi_epilogue
	ret
.cfi_endproc
.size	SHA3_squeeze,.-SHA3_squeeze
___
}
$code.=<<___;
.align	256
	.quad	0,0,0,0,0,0,0,0
.type	iotas,\@object
iotas:
	.quad	0x0000000000000001
	.quad	0x0000000000008082
	.quad	0x800000000000808a
	.quad	0x8000000080008000
	.quad	0x000000000000808b
	.quad	0x0000000080000001
	.quad	0x8000000080008081
	.quad	0x8000000000008009
	.quad	0x000000000000008a
	.quad	0x0000000000000088
	.quad	0x0000000080008009
	.quad	0x000000008000000a
	.quad	0x000000008000808b
	.quad	0x800000000000008b
	.quad	0x8000000000008089
	.quad	0x8000000000008003
	.quad	0x8000000000008002
	.quad	0x8000000000000080
	.quad	0x000000000000800a
	.quad	0x800000008000000a
	.quad	0x8000000080008081
	.quad	0x8000000000008080
	.quad	0x0000000080000001
	.quad	0x8000000080008008
.size	iotas,.-iotas
.asciz	"Keccak-1600 absorb and squeeze for x86_64 APX, CRYPTOGAMS by \@dot-asm"
___

print $code;

close STDOUT;

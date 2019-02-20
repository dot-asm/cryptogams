#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov, @dot-asm, initially for the OpenSSL
# project.
# ====================================================================
#
# December 2015
#
# ChaCha20 for s390x.
#
# 3 times faster than compiler-generated code.
#
# February 2019
#
# Add a transliteration of VSX code path from chacha20-ppc module.
# It minimizes reloads from memory, which seems to help under load, as
# it's more "cooperative" in a sense. Then a "horizontal" round was
# "braided in" to compensate for higher VX instruction latency. It's
# ~25% faster than IBM submission and >3 faster than scalar code.
#
# NB, compile with additional -Wa,-march=z13.

$flavour = shift;

if ($flavour =~ /3[12]/) {
	$SIZE_T=4;
	$g="";
} else {
	$SIZE_T=8;
	$g="g";
}

while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

sub AUTOLOAD()		# thunk [simplified] x86-style perlasm
{ my $opcode = $AUTOLOAD; $opcode =~ s/.*:://;
    $code .= "\t$opcode\t".join(',',@_)."\n";
}

my $sp="%r15";

my $stdframe=16*$SIZE_T+4*8;
my $frame=$stdframe+4*20;

my ($out,$inp,$len,$key,$counter)=map("%r$_",(2..6));

my @x=map("%r$_",(0..7,"x","x","x","x",(10..13)));
my @t=map("%r$_",(8,9));

sub ROUND {
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my ($xc,$xc_)=map("\"$_\"",@t);
my @x=map("\"$_\"",@x);

	# Consider order in which variables are addressed by their
	# index:
	#
	#	a   b   c   d
	#
	#	0   4   8  12 < even round
	#	1   5   9  13
	#	2   6  10  14
	#	3   7  11  15
	#	0   5  10  15 < odd round
	#	1   6  11  12
	#	2   7   8  13
	#	3   4   9  14
	#
	# 'a', 'b' and 'd's are permanently allocated in registers,
	# @x[0..7,12..15], while 'c's are maintained in memory. If
	# you observe 'c' column, you'll notice that pair of 'c's is
	# invariant between rounds. This means that we have to reload
	# them once per round, in the middle. This is why you'll see
	# 'c' stores and loads in the middle, but none in the beginning
	# or end.

	(
	"&alr	(@x[$a0],@x[$b0])",	# Q1
	 "&alr	(@x[$a1],@x[$b1])",	# Q2
	"&xr	(@x[$d0],@x[$a0])",
	 "&xr	(@x[$d1],@x[$a1])",
	"&rll	(@x[$d0],@x[$d0],16)",
	 "&rll	(@x[$d1],@x[$d1],16)",

	"&alr	($xc,@x[$d0])",
	 "&alr	($xc_,@x[$d1])",
	"&xr	(@x[$b0],$xc)",
	 "&xr	(@x[$b1],$xc_)",
	"&rll	(@x[$b0],@x[$b0],12)",
	 "&rll	(@x[$b1],@x[$b1],12)",

	"&alr	(@x[$a0],@x[$b0])",
	 "&alr	(@x[$a1],@x[$b1])",
	"&xr	(@x[$d0],@x[$a0])",
	 "&xr	(@x[$d1],@x[$a1])",
	"&rll	(@x[$d0],@x[$d0],8)",
	 "&rll	(@x[$d1],@x[$d1],8)",

	"&alr	($xc,@x[$d0])",
	 "&alr	($xc_,@x[$d1])",
	"&xr	(@x[$b0],$xc)",
	 "&xr	(@x[$b1],$xc_)",
	"&rll	(@x[$b0],@x[$b0],7)",
	 "&rll	(@x[$b1],@x[$b1],7)",

	"&stm	($xc,$xc_,'$stdframe+4*8+4*$c0($sp)')",	# reload pair of 'c's
	"&lm	($xc,$xc_,'$stdframe+4*8+4*$c2($sp)')",

	"&alr	(@x[$a2],@x[$b2])",	# Q3
	 "&alr	(@x[$a3],@x[$b3])",	# Q4
	"&xr	(@x[$d2],@x[$a2])",
	 "&xr	(@x[$d3],@x[$a3])",
	"&rll	(@x[$d2],@x[$d2],16)",
	 "&rll	(@x[$d3],@x[$d3],16)",

	"&alr	($xc,@x[$d2])",
	 "&alr	($xc_,@x[$d3])",
	"&xr	(@x[$b2],$xc)",
	 "&xr	(@x[$b3],$xc_)",
	"&rll	(@x[$b2],@x[$b2],12)",
	 "&rll	(@x[$b3],@x[$b3],12)",

	"&alr	(@x[$a2],@x[$b2])",
	 "&alr	(@x[$a3],@x[$b3])",
	"&xr	(@x[$d2],@x[$a2])",
	 "&xr	(@x[$d3],@x[$a3])",
	"&rll	(@x[$d2],@x[$d2],8)",
	 "&rll	(@x[$d3],@x[$d3],8)",

	"&alr	($xc,@x[$d2])",
	 "&alr	($xc_,@x[$d3])",
	"&xr	(@x[$b2],$xc)",
	 "&xr	(@x[$b3],$xc_)",
	"&rll	(@x[$b2],@x[$b2],7)",
	 "&rll	(@x[$b3],@x[$b3],7)"
	);
}

$code.=<<___;
.text

.globl	ChaCha20_ctr32
.type	ChaCha20_ctr32,\@function
.align	32
ChaCha20_ctr32:
	larl	%r1,OPENSSL_s390xcap_P
	lghi	%r0,64
	lt${g}r	$len,$len			# $len==0?
	bzr	%r14
	lg	%r1,16(%r1)
	cl${g}r	$len,%r0
	jle	.Lshort

	tmhh	%r1,0x4000			# check for vx bit
	jnz	.LChaCha20_ctr32_vx

.Lshort:
	a${g}hi	$len,-64
	l${g}hi	%r1,-$frame
	stm${g}	%r6,%r15,`6*$SIZE_T`($sp)
	sl${g}r	$out,$inp			# difference
	la	$len,0($inp,$len)		# end of input minus 64
	larl	%r7,.Lsigma
	lgr	%r0,$sp
	la	$sp,0(%r1,$sp)
	st${g}	%r0,0($sp)

	lmg	%r8,%r11,0($key)		# load key
	lmg	%r12,%r13,0($counter)		# load counter
	lmg	%r6,%r7,0(%r7)			# load sigma constant

	la	%r14,0($inp)
	st${g}	$out,$frame+3*$SIZE_T($sp)
	st${g}	$len,$frame+4*$SIZE_T($sp)
	stmg	%r6,%r13,$stdframe($sp)		# copy key schedule to stack
	srlg	@x[12],%r12,32			# 32-bit counter value

.align	16
.Loop_outer:
	lm	@x[0],@x[7],$stdframe+4*0($sp)		# load x[0]-x[7]
	lm	@t[0],@t[1],$stdframe+4*10($sp)		# load x[10]-x[11]
	lm	@x[13],@x[15],$stdframe+4*13($sp)	# load x[13]-x[15]
	stm	@t[0],@t[1],$stdframe+4*8+4*10($sp)	# offload x[10]-x[11]
	lm	@t[0],@t[1],$stdframe+4*8($sp)		# load x[8]-x[9]
	st	@x[12],$stdframe+4*12($sp)		# save counter
	st${g}	%r14,$frame+2*$SIZE_T($sp)		# save input pointer
	lhi	%r14,10
	j	.Loop

.align	4
.Loop:
___
	foreach (&ROUND(0, 4, 8,12)) { eval; }
	foreach (&ROUND(0, 5,10,15)) { eval; }
$code.=<<___;
	brct	%r14,.Loop

	l${g}	%r14,$frame+2*$SIZE_T($sp)		# pull input pointer
	stm	@t[0],@t[1],$stdframe+4*8+4*8($sp)	# offload x[8]-x[9]
	lm${g}	@t[0],@t[1],$frame+3*$SIZE_T($sp)

	al	@x[0],$stdframe+4*0($sp)	# accumulate key schedule
	al	@x[1],$stdframe+4*1($sp)
	al	@x[2],$stdframe+4*2($sp)
	al	@x[3],$stdframe+4*3($sp)
	al	@x[4],$stdframe+4*4($sp)
	al	@x[5],$stdframe+4*5($sp)
	al	@x[6],$stdframe+4*6($sp)
	al	@x[7],$stdframe+4*7($sp)
	lrvr	@x[0],@x[0]
	lrvr	@x[1],@x[1]
	lrvr	@x[2],@x[2]
	lrvr	@x[3],@x[3]
	lrvr	@x[4],@x[4]
	lrvr	@x[5],@x[5]
	lrvr	@x[6],@x[6]
	lrvr	@x[7],@x[7]
	al	@x[12],$stdframe+4*12($sp)
	al	@x[13],$stdframe+4*13($sp)
	al	@x[14],$stdframe+4*14($sp)
	al	@x[15],$stdframe+4*15($sp)
	lrvr	@x[12],@x[12]
	lrvr	@x[13],@x[13]
	lrvr	@x[14],@x[14]
	lrvr	@x[15],@x[15]

	la	@t[0],0(@t[0],%r14)		# reconstruct output pointer
	cl${g}r	%r14,@t[1]
	jh	.Ltail

	x	@x[0],4*0(%r14)			# xor with input
	x	@x[1],4*1(%r14)
	st	@x[0],4*0(@t[0])		# store output
	x	@x[2],4*2(%r14)
	st	@x[1],4*1(@t[0])
	x	@x[3],4*3(%r14)
	st	@x[2],4*2(@t[0])
	x	@x[4],4*4(%r14)
	st	@x[3],4*3(@t[0])
	 lm	@x[0],@x[3],$stdframe+4*8+4*8($sp)	# load x[8]-x[11]
	x	@x[5],4*5(%r14)
	st	@x[4],4*4(@t[0])
	x	@x[6],4*6(%r14)
	 al	@x[0],$stdframe+4*8($sp)
	st	@x[5],4*5(@t[0])
	x	@x[7],4*7(%r14)
	 al	@x[1],$stdframe+4*9($sp)
	st	@x[6],4*6(@t[0])
	x	@x[12],4*12(%r14)
	 al	@x[2],$stdframe+4*10($sp)
	st	@x[7],4*7(@t[0])
	x	@x[13],4*13(%r14)
	 al	@x[3],$stdframe+4*11($sp)
	st	@x[12],4*12(@t[0])
	x	@x[14],4*14(%r14)
	st	@x[13],4*13(@t[0])
	x	@x[15],4*15(%r14)
	st	@x[14],4*14(@t[0])
	 lrvr	@x[0],@x[0]
	st	@x[15],4*15(@t[0])
	 lrvr	@x[1],@x[1]
	 lrvr	@x[2],@x[2]
	 lrvr	@x[3],@x[3]
	lhi	@x[12],1
	 x	@x[0],4*8(%r14)
	al	@x[12],$stdframe+4*12($sp)	# increment counter
	 x	@x[1],4*9(%r14)
	 st	@x[0],4*8(@t[0])
	 x	@x[2],4*10(%r14)
	 st	@x[1],4*9(@t[0])
	 x	@x[3],4*11(%r14)
	 st	@x[2],4*10(@t[0])
	 st	@x[3],4*11(@t[0])

	cl${g}r	%r14,@t[1]			# done yet?
	la	%r14,64(%r14)
	jl	.Loop_outer

.Ldone:
	xgr	%r0,%r0
	xgr	%r1,%r1
	xgr	%r2,%r2
	xgr	%r3,%r3
	stmg	%r0,%r3,$stdframe+4*4($sp)	# wipe key copy
	stmg	%r0,%r3,$stdframe+4*12($sp)

	lm${g}	%r6,%r15,`$frame+6*$SIZE_T`($sp)
	br	%r14

.align	16
.Ltail:
	la	@t[1],64($t[1])
	stm	@x[0],@x[7],$stdframe+4*0($sp)
	sl${g}r	@t[1],%r14
	lm	@x[0],@x[3],$stdframe+4*8+4*8($sp)
	l${g}hi	@x[6],0
	stm	@x[12],@x[15],$stdframe+4*12($sp)
	al	@x[0],$stdframe+4*8($sp)
	al	@x[1],$stdframe+4*9($sp)
	al	@x[2],$stdframe+4*10($sp)
	al	@x[3],$stdframe+4*11($sp)
	lrvr	@x[0],@x[0]
	lrvr	@x[1],@x[1]
	lrvr	@x[2],@x[2]
	lrvr	@x[3],@x[3]
	stm	@x[0],@x[3],$stdframe+4*8($sp)

.Loop_tail:
	llgc	@x[4],0(@x[6],%r14)
	llgc	@x[5],$stdframe(@x[6],$sp)
	xr	@x[5],@x[4]
	stc	@x[5],0(@x[6],@t[0])
	la	@x[6],1(@x[6])
	brct	@t[1],.Loop_tail

	j	.Ldone
.size	ChaCha20_ctr32,.-ChaCha20_ctr32
___
{{{
my ($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
    $xc0,$xc1,$xc2,$xc3, $xd0,$xd1,$xd2,$xd3) = map("%v$_",(0..15));
my @K = map("%v$_",(16..19));
my $CTR = "%v26";
my ($xt0,$xt1,$xt2,$xt3) = map("%v$_",(27..30));
my $beperm = "%v31";

my $FRAME=$stdframe + 4*16 + ($flavour =~ /64/? 8*8 : 0);

sub VX_lane_ROUND {
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my @x=map("\"%v$_\"",(0..15));
my ($a4,$b4,$c4,$d4)=map("\"$_\"",($xt0,$xt1,$xt2,$xt3));
my $odd = ($b0 & 1);

	(
	"&vaf		($a4,$a4,$b4)",			# "horizontal"
	 "&vaf		(@x[$a0],@x[$a0],@x[$b0])",	# Q1
	  "&vaf		(@x[$a1],@x[$a1],@x[$b1])",	# Q2
	   "&vaf	(@x[$a2],@x[$a2],@x[$b2])",	# Q3
	    "&vaf	(@x[$a3],@x[$a3],@x[$b3])",	# Q4
	"&vx		($d4,$d4,$a4)",
	 "&vx		(@x[$d0],@x[$d0],@x[$a0])",
	  "&vx		(@x[$d1],@x[$d1],@x[$a1])",
	   "&vx		(@x[$d2],@x[$d2],@x[$a2])",
	    "&vx	(@x[$d3],@x[$d3],@x[$a3])",
	"&verllf	($d4,$d4,16)",
	 "&verllf	(@x[$d0],@x[$d0],16)",
	  "&verllf	(@x[$d1],@x[$d1],16)",
	   "&verllf	(@x[$d2],@x[$d2],16)",
	    "&verllf	(@x[$d3],@x[$d3],16)",

	"&vaf		($c4,$c4,$d4)",
	 "&vaf		(@x[$c0],@x[$c0],@x[$d0])",
	  "&vaf		(@x[$c1],@x[$c1],@x[$d1])",
	   "&vaf	(@x[$c2],@x[$c2],@x[$d2])",
	    "&vaf	(@x[$c3],@x[$c3],@x[$d3])",
	"&vx		($b4,$b4,$c4)",
	 "&vx		(@x[$b0],@x[$b0],@x[$c0])",
	  "&vx		(@x[$b1],@x[$b1],@x[$c1])",
	   "&vx		(@x[$b2],@x[$b2],@x[$c2])",
	    "&vx	(@x[$b3],@x[$b3],@x[$c3])",
	"&verllf	($b4,$b4,12)",
	 "&verllf	(@x[$b0],@x[$b0],12)",
	  "&verllf	(@x[$b1],@x[$b1],12)",
	   "&verllf	(@x[$b2],@x[$b2],12)",
	    "&verllf	(@x[$b3],@x[$b3],12)",

	"&vaf		($a4,$a4,$b4)",
	 "&vaf		(@x[$a0],@x[$a0],@x[$b0])",
	  "&vaf		(@x[$a1],@x[$a1],@x[$b1])",
	   "&vaf	(@x[$a2],@x[$a2],@x[$b2])",
	    "&vaf	(@x[$a3],@x[$a3],@x[$b3])",
	"&vx		($d4,$d4,$a4)",
	 "&vx		(@x[$d0],@x[$d0],@x[$a0])",
	  "&vx		(@x[$d1],@x[$d1],@x[$a1])",
	   "&vx		(@x[$d2],@x[$d2],@x[$a2])",
	    "&vx	(@x[$d3],@x[$d3],@x[$a3])",
	"&verllf	($d4,$d4,8)",
	 "&verllf	(@x[$d0],@x[$d0],8)",
	  "&verllf	(@x[$d1],@x[$d1],8)",
	   "&verllf	(@x[$d2],@x[$d2],8)",
	    "&verllf	(@x[$d3],@x[$d3],8)",

	"&vaf		($c4,$c4,$d4)",
	 "&vaf		(@x[$c0],@x[$c0],@x[$d0])",
	  "&vaf		(@x[$c1],@x[$c1],@x[$d1])",
	   "&vaf	(@x[$c2],@x[$c2],@x[$d2])",
	    "&vaf	(@x[$c3],@x[$c3],@x[$d3])",
	"&vx		($b4,$b4,$c4)",
	"&vsldb		($c4,$c4,$c4,8)",
	 "&vx		(@x[$b0],@x[$b0],@x[$c0])",
	  "&vx		(@x[$b1],@x[$b1],@x[$c1])",
	   "&vx		(@x[$b2],@x[$b2],@x[$c2])",
	    "&vx	(@x[$b3],@x[$b3],@x[$c3])",
	"&verllf	($b4,$b4,7)",
	"&vsldb		($b4,$b4,$b4,$odd ? 12 : 4)",
	 "&verllf	(@x[$b0],@x[$b0],7)",
	  "&verllf	(@x[$b1],@x[$b1],7)",
	   "&verllf	(@x[$b2],@x[$b2],7)",
	    "&verllf	(@x[$b3],@x[$b3],7)",
	"&vsldb		($d4,$d4,$d4,$odd ? 4 : 12)"
	);
}

$code.=<<___;
.globl	ChaCha20_ctr32_vx
.align	32
ChaCha20_ctr32_vx:
.LChaCha20_ctr32_vx:
	stm${g}	%r6,%r7,`6*$SIZE_T`($sp)
___
$code.=<<___	if ($flavour !~ /64/);
	std	%f4,`16*$SIZE_T+2*8`($sp)
	std	%f6,`16*$SIZE_T+3*8`($sp)
___
$code.=<<___;
	l${g}hi	%r1,-$FRAME
	lgr	%r0,$sp
	la	$sp,0(%r1,$sp)
	st${g}	%r0,0($sp)			# back-chain
___
$code.=<<___	if ($flavour =~ /64/);
	std	%f8,`$FRAME-8*8`($sp)
	std	%f9,`$FRAME-8*7`($sp)
	std	%f10,`$FRAME-8*6`($sp)
	std	%f11,`$FRAME-8*5`($sp)
	std	%f12,`$FRAME-8*4`($sp)
	std	%f13,`$FRAME-8*3`($sp)
	std	%f14,`$FRAME-8*2`($sp)
	std	%f15,`$FRAME-8*1`($sp)
___
$code.=<<___;
	larl	%r7,.Lsigma

	vl	@K[0],0(%r7)			# load sigma
	vl	@K[1],0($key)			# load key
	vl	@K[2],16($key)
	vl	@K[3],0($counter)		# load counter

	vl	$xt1,0x50(%r7)
	vl	$beperm,0x60(%r7)
	vrepf	$CTR,@K[3],0
	vaf	$CTR,$CTR,$xt1

	llgf	$counter,0($counter)
	ahi	$counter,4
	lghi	%r1,0
	lhi	%r0,10

.Loop_outer_vx:
	vlm	$xa0,$xa3,0x10(%r7)		# load [smashed] sigma
	vlr	$xt0,@K[0]
	vlvgf	@K[3],$counter,0

	vrepf	$xb0,@K[1],0			# smash the key
	vrepf	$xb1,@K[1],1
	vrepf	$xb2,@K[1],2
	vrepf	$xb3,@K[1],3
	vlr	$xt1,@K[1]

	vrepf	$xc0,@K[2],0
	vrepf	$xc1,@K[2],1
	vrepf	$xc2,@K[2],2
	vrepf	$xc3,@K[2],3
	vlr	$xt2,@K[2]

	vlr	$xd0,$CTR
	vrepf	$xd1,@K[3],1
	vrepf	$xd2,@K[3],2
	vrepf	$xd3,@K[3],3
	vlr	$xt3,@K[3]

.Loop_vx:
___
	foreach (&VX_lane_ROUND(0, 4, 8,12)) { eval; }
	foreach (&VX_lane_ROUND(0, 5,10,15)) { eval; }
$code.=<<___;
	brct	%r0,.Loop_vx

	vaf	$xt0,$xt0,@K[0]
	vaf	$xt1,$xt1,@K[1]
	vaf	$xt2,$xt2,@K[2]
	vaf	$xt3,$xt3,@K[3]
	vaf	$xd0,$xd0,$CTR

	vstm	$xt0,$xt3,$stdframe($sp)	# offload "horizontal" round

	vmrhf	$xt0,$xa0,$xa1			# transpose data
	vmrhf	$xt1,$xa2,$xa3
	vmrlf	$xt2,$xa0,$xa1
	vmrlf	$xt3,$xa2,$xa3
	vpdi	$xa0,$xt0,$xt1,0b0000
	vpdi	$xa1,$xt0,$xt1,0b0101
	vpdi	$xa2,$xt2,$xt3,0b0000
	vpdi	$xa3,$xt2,$xt3,0b0101

	vmrhf	$xt0,$xb0,$xb1
	vmrhf	$xt1,$xb2,$xb3
	vmrlf	$xt2,$xb0,$xb1
	vmrlf	$xt3,$xb2,$xb3
	vpdi	$xb0,$xt0,$xt1,0b0000
	vpdi	$xb1,$xt0,$xt1,0b0101
	vpdi	$xb2,$xt2,$xt3,0b0000
	vpdi	$xb3,$xt2,$xt3,0b0101

	vmrhf	$xt0,$xc0,$xc1
	vmrhf	$xt1,$xc2,$xc3
	vmrlf	$xt2,$xc0,$xc1
	vmrlf	$xt3,$xc2,$xc3
	vpdi	$xc0,$xt0,$xt1,0b0000
	vpdi	$xc1,$xt0,$xt1,0b0101
	vpdi	$xc2,$xt2,$xt3,0b0000
	vpdi	$xc3,$xt2,$xt3,0b0101

	vmrhf	$xt0,$xd0,$xd1
	vmrhf	$xt1,$xd2,$xd3
	vmrlf	$xt2,$xd0,$xd1
	vmrlf	$xt3,$xd2,$xd3
	vpdi	$xd0,$xt0,$xt1,0b0000
	vpdi	$xd1,$xt0,$xt1,0b0101
	vpdi	$xd2,$xt2,$xt3,0b0000
	vpdi	$xd3,$xt2,$xt3,0b0101

	vrepif	$xt0,5
	vlvgf	@K[3],%r1,0			# clear @K[3].word[0]
	vaf	$CTR,$CTR,$xt0			# next counter value

	vaf	$xa0,$xa0,@K[0]
	vaf	$xb0,$xb0,@K[1]
	vaf	$xc0,$xc0,@K[2]
	vaf	$xd0,$xd0,@K[3]

	vperm	$xa0,$xa0,$xa0,$beperm
	vperm	$xb0,$xb0,$xb0,$beperm
	vperm	$xc0,$xc0,$xc0,$beperm
	vperm	$xd0,$xd0,$xd0,$beperm

	cl${g}fi $len,0x40
	jl	.Ltail_vx

	vlm	$xt0,$xt3,0($inp)

	vx	$xt0,$xt0,$xa0
	vx	$xt1,$xt1,$xb0
	vx	$xt2,$xt2,$xc0
	vx	$xt3,$xt3,$xd0

	vstm	$xt0,$xt3,0($out)

	la	$inp,0x40($inp)
	la	$out,0x40($out)
	a${g}hi	$len,-0x40
	je	.Ldone_vx

	vaf	$xa0,$xa1,@K[0]
	vaf	$xb0,$xb1,@K[1]
	vaf	$xc0,$xc1,@K[2]
	vaf	$xd0,$xd1,@K[3]

	vperm	$xa0,$xa0,$xa0,$beperm
	vperm	$xb0,$xb0,$xb0,$beperm
	vperm	$xc0,$xc0,$xc0,$beperm
	vperm	$xd0,$xd0,$xd0,$beperm

	cl${g}fi $len,0x40
	jl	.Ltail_vx

	vlm	$xt0,$xt3,0($inp)

	vx	$xt0,$xt0,$xa0
	vx	$xt1,$xt1,$xb0
	vx	$xt2,$xt2,$xc0
	vx	$xt3,$xt3,$xd0

	vstm	$xt0,$xt3,0($out)

	la	$inp,0x40($inp)
	la	$out,0x40($out)
	a${g}hi	$len,-0x40
	je	.Ldone_vx

	vaf	$xa0,$xa2,@K[0]
	vaf	$xb0,$xb2,@K[1]
	vaf	$xc0,$xc2,@K[2]
	vaf	$xd0,$xd2,@K[3]

	vperm	$xa0,$xa0,$xa0,$beperm
	vperm	$xb0,$xb0,$xb0,$beperm
	vperm	$xc0,$xc0,$xc0,$beperm
	vperm	$xd0,$xd0,$xd0,$beperm

	cl${g}fi $len,0x40
	jl	.Ltail_vx

	vlm	$xt0,$xt3,0($inp)

	vx	$xt0,$xt0,$xa0
	vx	$xt1,$xt1,$xb0
	vx	$xt2,$xt2,$xc0
	vx	$xt3,$xt3,$xd0

	vstm	$xt0,$xt3,0($out)

	la	$inp,0x40($inp)
	la	$out,0x40($out)
	a${g}hi	$len,-0x40
	je	.Ldone_vx

	vaf	$xa0,$xa3,@K[0]
	vaf	$xb0,$xb3,@K[1]
	vaf	$xc0,$xc3,@K[2]
	vaf	$xd0,$xd3,@K[3]

	vperm	$xa0,$xa0,$xa0,$beperm
	vperm	$xb0,$xb0,$xb0,$beperm
	vperm	$xc0,$xc0,$xc0,$beperm
	vperm	$xd0,$xd0,$xd0,$beperm

	cl${g}fi $len,0x40
	jl	.Ltail_vx

	vlm	$xt0,$xt3,0($inp)

	vx	$xt0,$xt0,$xa0
	vx	$xt1,$xt1,$xb0
	vx	$xt2,$xt2,$xc0
	vx	$xt3,$xt3,$xd0

	vstm	$xt0,$xt3,0($out)

	la	$inp,0x40($inp)
	la	$out,0x40($out)
	a${g}hi	$len,-0x40
	je	.Ldone_vx

	vlm	$xt0,$xt3,$stdframe($sp)

	vperm	$xa0,$xt0,$xt0,$beperm
	vperm	$xb0,$xt1,$xt1,$beperm
	vperm	$xc0,$xt2,$xt2,$beperm
	vperm	$xd0,$xt3,$xt3,$beperm

	ahi	$counter,5
	cl${g}fi $len,0x40
	jl	.Ltail_vx

	vlm	$xt0,$xt3,0($inp)

	vx	$xt0,$xt0,$xa0
	vx	$xt1,$xt1,$xb0
	vx	$xt2,$xt2,$xc0
	vx	$xt3,$xt3,$xd0

	vstm	$xt0,$xt3,0($out)

	la	$inp,0x40($inp)
	la	$out,0x40($out)
	lhi	%r0,10
	a${g}hi	$len,-0x40
	jne	.Loop_outer_vx

.Ldone_vx:
___
$code.=<<___	if ($flavour !~ /64/);
	ld	%f4,`$FRAME+16*$SIZE_T+2*8`($sp)
	ld	%f6,`$FRAME+16*$SIZE_T+3*8`($sp)
___
$code.=<<___	if ($flavour =~ /64/);
	ld	%f8,`$FRAME-8*8`($sp)
	ld	%f9,`$FRAME-8*7`($sp)
	ld	%f10,`$FRAME-8*6`($sp)
	ld	%f11,`$FRAME-8*5`($sp)
	ld	%f12,`$FRAME-8*4`($sp)
	ld	%f13,`$FRAME-8*3`($sp)
	ld	%f14,`$FRAME-8*2`($sp)
	ld	%f15,`$FRAME-8*1`($sp)
___
$code.=<<___;
	lm${g}	%r6,%r7,`$FRAME+6*$SIZE_T`($sp)
	la	$sp,$FRAME($sp)
	br	%r14

.align	16
.Ltail_vx:
___
$code.=<<___	if ($flavour !~ /64/);
	vlr	$xt0,$xb0
	ld	%f4,`$FRAME+16*$SIZE_T+2*8`($sp)
	ld	%f6,`$FRAME+16*$SIZE_T+3*8`($sp)

	vst	$xa0,`$stdframe+0x00`($sp)
	vst	$xt0,`$stdframe+0x10`($sp)
	vst	$xc0,`$stdframe+0x20`($sp)
	vst	$xd0,`$stdframe+0x30`($sp)
___
$code.=<<___	if ($flavour =~ /64/);
	vlr	$xt0,$xc0
	ld	%f8,`$FRAME-8*8`($sp)
	ld	%f9,`$FRAME-8*7`($sp)
	ld	%f10,`$FRAME-8*6`($sp)
	ld	%f11,`$FRAME-8*5`($sp)
	vlr	$xt1,$xd0
	ld	%f12,`$FRAME-8*4`($sp)
	ld	%f13,`$FRAME-8*3`($sp)
	ld	%f14,`$FRAME-8*2`($sp)
	ld	%f15,`$FRAME-8*1`($sp)

	vst	$xa0,`$stdframe+0x00`($sp)
	vst	$xb0,`$stdframe+0x10`($sp)
	vst	$xt0,`$stdframe+0x20`($sp)
	vst	$xt1,`$stdframe+0x30`($sp)
___
$code.=<<___;
	lghi	%r1,0

.Loop_tail_vx:
	llgc	%r5,0(%r1,$inp)
	llgc	%r6,$stdframe(%r1,$sp)
	xr	%r6,%r5
	stc	%r6,0(%r1,$out)
	la	%r1,1(%r1)
	brct	$len,.Loop_tail_vx

	lm${g}	%r6,%r7,`$FRAME+6*$SIZE_T`($sp)
	la	$sp,$FRAME($sp)
	br	%r14
.size	ChaCha20_ctr32_vx,.-ChaCha20_ctr32_vx
___
}}}
$code.=<<___;
.align	32
.Lsigma:
.long	0x61707865,0x3320646e,0x79622d32,0x6b206574	# endian-neutral

.long	0x61707865,0x61707865,0x61707865,0x61707865	# smashed sigma
.long	0x3320646e,0x3320646e,0x3320646e,0x3320646e
.long	0x79622d32,0x79622d32,0x79622d32,0x79622d32
.long	0x6b206574,0x6b206574,0x6b206574,0x6b206574

.long	0,1,2,3

.long	0x03020100,0x07060504,0x0b0a0908,0x0f0e0d0c	# byte swap

.asciz	"ChaCha20 for s390x, CRYPTOGAMS by \@dot-asm"
.align	4
___

foreach (split("\n",$code)) {
	s/\`([^\`]*)\`/eval $1/ge;

	print $_,"\n";
}
close STDOUT;

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
######################################################################
#
($zero,$ra,$sp,$gp,$tp) = map("x$_",(0..4));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("x$_",(10..17));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8,$s9,$s10,$s11)=map("x$_",(8,9,18..27));
($t0,$t1,$t2,$t3,$t4,$t5,$t6)=map("x$_",(5..7, 28..31));
#
$flavour = shift || "64";

if ($flavour =~ /64/) {
	$REG_S="sd";
	$REG_L="ld";
	$SRL="srlw";
	$SZREG=8;
} else {
	$REG_S="sw";
	$REG_L="lw";
	$PTR_SLL="sll";
	$SRL="srl";
	$SZREG=4;
}

$FRAMESIZE=64+16*$SZREG;
$SAVED_REGS_MASK = ($flavour =~ /nubi/i) ? "0xc0fff008" : "0xc0ff0000";
#
######################################################################

my @x = map("x$_",(16..31));
my @y = map("x$_",(5..9,14,15));
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
	$SRL		@y[0],@x[$d0],16
	 $SRL		@y[1],@x[$d1],16
	  $SRL		@y[2],@x[$d2],16
	   $SRL		@y[3],@x[$d3],16
	sll		@x[$d0],@x[$d0],16
	 sll		@x[$d1],@x[$d1],16
	  sll		@x[$d2],@x[$d2],16
	   sll		@x[$d3],@x[$d3],16
	or		@x[$d0],@x[$d0],@y[0]
	 or		@x[$d1],@x[$d1],@y[1]
	  or		@x[$d2],@x[$d2],@y[2]
	   or		@x[$d3],@x[$d3],@y[3]

	add		@x[$c0],@x[$c0],@x[$d0]
	 add		@x[$c1],@x[$c1],@x[$d1]
	  add		@x[$c2],@x[$c2],@x[$d2]
	   add		@x[$c3],@x[$c3],@x[$d3]
	xor		@x[$b0],@x[$b0],@x[$c0]
	 xor		@x[$b1],@x[$b1],@x[$c1]
	  xor		@x[$b2],@x[$b2],@x[$c2]
	   xor		@x[$b3],@x[$b3],@x[$c3]
	$SRL		@y[0],@x[$b0],20
	 $SRL		@y[1],@x[$b1],20
	  $SRL		@y[2],@x[$b2],20
	   $SRL		@y[3],@x[$b3],20
	sll		@x[$b0],@x[$b0],12
	 sll		@x[$b1],@x[$b1],12
	  sll		@x[$b2],@x[$b2],12
	   sll		@x[$b3],@x[$b3],12
	or		@x[$b0],@x[$b0],@y[0]
	 or		@x[$b1],@x[$b1],@y[1]
	  or		@x[$b2],@x[$b2],@y[2]
	   or		@x[$b3],@x[$b3],@y[3]

	add		@x[$a0],@x[$a0],@x[$b0]
	 add		@x[$a1],@x[$a1],@x[$b1]
	  add		@x[$a2],@x[$a2],@x[$b2]
	   add		@x[$a3],@x[$a3],@x[$b3]
	xor		@x[$d0],@x[$d0],@x[$a0]
	 xor		@x[$d1],@x[$d1],@x[$a1]
	  xor		@x[$d2],@x[$d2],@x[$a2]
	   xor		@x[$d3],@x[$d3],@x[$a3]
	$SRL		@y[0],@x[$d0],24
	 $SRL		@y[1],@x[$d1],24
	  $SRL		@y[2],@x[$d2],24
	   $SRL		@y[3],@x[$d3],24
	sll		@x[$d0],@x[$d0],8
	 sll		@x[$d1],@x[$d1],8
	  sll		@x[$d2],@x[$d2],8
	   sll		@x[$d3],@x[$d3],8
	or		@x[$d0],@x[$d0],@y[0]
	 or		@x[$d1],@x[$d1],@y[1]
	  or		@x[$d2],@x[$d2],@y[2]
	   or		@x[$d3],@x[$d3],@y[3]

	add		@x[$c0],@x[$c0],@x[$d0]
	 add		@x[$c1],@x[$c1],@x[$d1]
	  add		@x[$c2],@x[$c2],@x[$d2]
	   add		@x[$c3],@x[$c3],@x[$d3]
	xor		@x[$b0],@x[$b0],@x[$c0]
	 xor		@x[$b1],@x[$b1],@x[$c1]
	  xor		@x[$b2],@x[$b2],@x[$c2]
	   xor		@x[$b3],@x[$b3],@x[$c3]
	$SRL		@y[0],@x[$b0],25
	 $SRL		@y[1],@x[$b1],25
	  $SRL		@y[2],@x[$b2],25
	   $SRL		@y[3],@x[$b3],25
	sll		@x[$b0],@x[$b0],7
	 sll		@x[$b1],@x[$b1],7
	  sll		@x[$b2],@x[$b2],7
	   sll		@x[$b3],@x[$b3],7
	or		@x[$b0],@x[$b0],@y[0]
	 or		@x[$b1],@x[$b1],@y[1]
	  or		@x[$b2],@x[$b2],@y[2]
	   or		@x[$b3],@x[$b3],@y[3]
___
}

$code.=<<___;
.text

.globl	ChaCha20_ctr32
.type	ChaCha20_ctr32,\@function
ChaCha20_ctr32:
	addi		$sp,$sp,-$FRAMESIZE
	$REG_S		$ra, ($FRAMESIZE-1*$SZREG)($sp)
	$REG_S		$s0, ($FRAMESIZE-2*$SZREG)($sp)
	$REG_S		$s1, ($FRAMESIZE-3*$SZREG)($sp)
	$REG_S		$s2, ($FRAMESIZE-4*$SZREG)($sp)
	$REG_S		$s3, ($FRAMESIZE-5*$SZREG)($sp)
	$REG_S		$s4, ($FRAMESIZE-6*$SZREG)($sp)
	$REG_S		$s5, ($FRAMESIZE-7*$SZREG)($sp)
	$REG_S		$s6, ($FRAMESIZE-8*$SZREG)($sp)
	$REG_S		$s7, ($FRAMESIZE-9*$SZREG)($sp)
	$REG_S		$s8, ($FRAMESIZE-10*$SZREG)($sp)
	$REG_S		$s9, ($FRAMESIZE-11*$SZREG)($sp)
	$REG_S		$s10,($FRAMESIZE-12*$SZREG)($sp)
	$REG_S		$s11,($FRAMESIZE-13*$SZREG)($sp)

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
	mv		$ra,@x[12]
	sw		@x[13],4*13($sp)
	sw		@x[14],4*14($sp)
	sw		@x[15],4*15($sp)
	li		$at,10

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
	sltiu		$at,$len,64
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
	add		@x[12],@x[12],$ra
	add		@x[13],@x[13],@y[1]
	add		@x[14],@x[14],@y[2]
	add		@x[15],@x[15],@y[3]
	bnez		$at,.Ltail

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
	addi		$ra,$ra,1		# next counter value
	sb		@y[4],61($out)
	addi		$len,$len,-64
	sb		@y[5],62($out)
	addi		$inp,$inp,64
	sb		@y[6],63($out)
	addi		$out,$out,64
	beqz		$len,.Ldone

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
	mv		@x[12],$ra
	lw		@x[13],4*13($sp)
	lw		@x[14],4*14($sp)
	lw		@x[15],4*15($sp)
	li		$at,10
	j		.Loop

.Ltail:
	mv		$ra,$sp
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

	addi		$ra,$ra,4
	lb		@y[0],0($inp)
	lb		@y[1],1($inp)
	lb		@y[2],2($inp)
	addi		$len,$len,-4
	lb		@y[3],3($inp)
	addi		$inp,$inp,4
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
	addi		$out,$out,4
	j		.Loop_tail

.Last_word:
	beqz		$len,.Ldone
	addi		$len,$len,-1
	lb		@y[0],0($inp)
	addi		$inp,$inp,1
	xor		@y[0],@y[0],@x[0]
	srl		@x[0],@x[0],8
	sb		@y[0],0($out)
	addi		$out,$out,1
	j		.Last_word

.Ldone:
	$REG_L		$ra, ($FRAMESIZE-1*$SZREG)($sp)
	$REG_L		$s0, ($FRAMESIZE-2*$SZREG)($sp)
	$REG_L		$s1, ($FRAMESIZE-3*$SZREG)($sp)
	$REG_L		$s2, ($FRAMESIZE-4*$SZREG)($sp)
	$REG_L		$s3, ($FRAMESIZE-5*$SZREG)($sp)
	$REG_L		$s4, ($FRAMESIZE-6*$SZREG)($sp)
	$REG_L		$s5, ($FRAMESIZE-7*$SZREG)($sp)
	$REG_L		$s6, ($FRAMESIZE-8*$SZREG)($sp)
	$REG_L		$s7, ($FRAMESIZE-9*$SZREG)($sp)
	$REG_L		$s8, ($FRAMESIZE-10*$SZREG)($sp)
	$REG_L		$s9, ($FRAMESIZE-11*$SZREG)($sp)
	$REG_L		$s10,($FRAMESIZE-12*$SZREG)($sp)
	$REG_L		$s11,($FRAMESIZE-13*$SZREG)($sp)
	addi		$sp,$sp,$FRAMESIZE
	ret
.size	ChaCha20_ctr32,.-ChaCha20_ctr32
___

print $code;
close STDOUT;

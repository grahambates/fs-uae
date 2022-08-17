
EXECBASE = 4
DOSBASE = 8
FILENAME = 12
COMMANDLINE = 16
COMMANDSIZE = 20
NEWCOMMANDLINE = 24
STACKFRAME = 28
UAEFUNC = 32
FILEHANDLE = 36
MEMORY = 40
FILELEN = 44
TASK = 48
STACKSIZE = 52
OK = 56
CLI_MODULE = 60
CLI_COMMANDNAME = 64
CLI_ARGUMENTS = 68
NEWSTACK = 72
CLI = 76
NEWSEGMENT = 80
CLI_RETURNADDR = 84
DBGFILEHANDLE = 88
DBGMEMORY = 92
DBGFILELEN = 96

STACKSWAP = 128
CMDFILENAME = 160
DBGFILENAME = 416

DATA_SIZE = 1024

start
	pea exit(pc)
	movem.l d0-d7/a0-a6,-(sp)
	lea data,a5
	move.l sp,STACKFRAME(a5)
	move.l d0,COMMANDSIZE(a5)
	move.l a0,COMMANDLINE(a5)

	move.l 4.w,a6
	move.l a6,EXECBASE(a5)
	lea uaeres(pc),a1
	jsr -$1f2(a6) ;OpenResource
	tst.l d0
	beq quit
	move.l d0,a6
	lea funcname(pc),a0
	jsr -6(a6)
	tst.l d0
	beq quit
	move.l d0,UAEFUNC(a5)

	move.l EXECBASE(a5),a6
	lea dos(pc),a1
	moveq #0,d0
	jsr -$228(a6) ;OpenLibrary
	move.l d0,DOSBASE(a5)
	
	move.l COMMANDLINE(a5),a3
	move.l COMMANDSIZE(a5),d5
	move.l a3,a2
	move.l a3,a1
	moveq #' ',d0
	cmp.b #'"',(a3)
	bne.s nextchar
	moveq #'"',d0
	lea 1(a3),a2
	subq.l #1,d5
	bmi.w quit2
	move.l a3,a1
nextchar
	addq.l #1,a1
	subq.l #1,d5
	bmi.w quit2
	cmp.b #10,(a1)
	beq.s nextspace
	cmp.b (a1),d0
	bne.s nextchar
nextspace
	clr.b (a1)+
	subq.l #1,d5
	bmi.s endline
	cmp.b #' ',(a1)
	beq.s nextspace
endline
	tst.l d5
	bne.s notendline
	moveq #1,d5
	move.b #10,(a1)
	clr.b 1(a1)
notendline
	move.l a2,FILENAME(a5)
	move.l d5,(sp) ; d0 in stack
	move.l a1,8*4(sp) ; a0 in stack
	move.l a1,NEWCOMMANDLINE(a5)

	; fileload

	move.l DOSBASE(a5),a6
	move.l FILENAME(a5),d1
	move.l #1005,d2
	jsr -$1e(a6) ;Open
	move.l d0,FILEHANDLE(a5)
	beq quit2
	
	move.l FILEHANDLE(a5),d1
	moveq #0,d2
	moveq #1,d3 ;end
	jsr -$42(a6) ;Seek
	move.l FILEHANDLE(a5),d1
	moveq #0,d2
	moveq #-1,d3 ;beginning
	jsr -$42(a6) ;Seek
	move.l d0,FILELEN(a5)
	ble quit3
	
	move.l EXECBASE(a5),a6
	move.l FILELEN(a5),d0
	move.l #65536,d1
	jsr -$c6(a6) ;AllocMem
	move.l d0,MEMORY(a5)
	tst.l d0
	beq quit3
	
	move.l DOSBASE(a5),a6
	move.l FILEHANDLE(a5),d1
	move.l MEMORY(a5),d2
	move.l FILELEN(a5),d3
	jsr -$2a(a6) ;Read
	cmp.l FILELEN(a5),d0
	bne quit3

	; debugfileload
	move.l FILENAME(a5),a0
	lea DBGFILENAME(a5),a1
dbgfnc1
	move.b (a0)+,(a1)+
	bne.s dbgfnc1
	move.b #'.',-1(a1)
	lea dbgext(pc),a0
dbgfnc2
	move.b (a0)+,(a1)+
	bne.s dbgfnc2

	move.l DOSBASE(a5),a6
	lea DBGFILENAME(a5),a0
	move.l a0,d1
	move.l #1005,d2
	jsr -$1e(a6) ;Open
	move.l d0,DBGFILEHANDLE(a5)
	beq nodbgfile
	
	move.l DBGFILEHANDLE(a5),d1
	moveq #0,d2
	moveq #1,d3 ;end
	jsr -$42(a6) ;Seek
	move.l DBGFILEHANDLE(a5),d1
	moveq #0,d2
	moveq #-1,d3 ;beginning
	jsr -$42(a6) ;Seek
	move.l d0,DBGFILELEN(a5)
	ble quit3
	
	move.l EXECBASE(a5),a6
	move.l DBGFILELEN(a5),d0
	move.l #65536,d1
	jsr -$c6(a6) ;AllocMem
	move.l d0,DBGMEMORY(a5)
	tst.l d0
	beq nodbgfile
	
	move.l DOSBASE(a5),a6
	move.l DBGFILEHANDLE(a5),d1
	move.l DBGMEMORY(a5),d2
	move.l DBGFILELEN(a5),d3
	jsr -$2a(a6) ;Read
	cmp.l DBGFILELEN(a5),d0
	bne quit3	
nodbgfile

	move.l EXECBASE(a5),a6
	sub.l a1,a1
	jsr -$126(a6) ;FindTask
	move.l d0,TASK(a5)

	move.l TASK(a5),a1
	move.l #200,d1
	move.l 62(a1),d3 ;SPUpper
	sub.l 58(a1),d3 ;SPLower
	move.l d3,STACKSIZE(a5)
	move.l MEMORY(a5),a0
	move.l FILELEN(a5),d0
	move.l DBGMEMORY(a5),a2
	move.l DBGFILELEN(a5),d2
	move.l UAEFUNC(a5),a4
	moveq #1,d4
	jsr (a4) ; call uae trap
	tst.l d0
	beq quit3
	; d2 = new stack start address
	move.l d0,(8+7)*4(sp)
	move.l d0,NEWSEGMENT(a5)
	move.l d2,NEWSTACK(a5)

	move.l TASK(a5),a2
	move.l 204(a2),CLI_ARGUMENTS(a5) ;pr_Arguments
	move.l NEWCOMMANDLINE(a5),204(a2)
	move.l 176(a2),CLI_RETURNADDR(a5) ;pr_ReturnAddr
	move.l 172(a2),a1 ;pr_CLI
	add.l a1,a1
	add.l a1,a1
	move.l a1,CLI(a5)
	
	moveq #-1,d0
	move.l FILENAME(a5),a0
	lea CMDFILENAME(a5),a1
	lea 1(a1),a2
copyname
	addq.b #1,d0
	move.b (a0)+,(a2)+
	bne.s copyname
	move.b d0,(a1)
	move.l a1,d0
	lsr.l #2,d0
	move.l CLI(a5),a0
	
	move.l 16(a0),CLI_COMMANDNAME(a5)
	move.l 60(a0),CLI_MODULE(a5)
	move.l d0,16(a0) ;cli_CommandName
	move.l NEWSEGMENT(a5),d0
	lsr.l #2,d0
	subq.l #1,d0
	move.l d0,60(a0) ;cli_Module

	st OK(a5)

quit3
	move.l DOSBASE(a5),a6
	move.l FILEHANDLE(a5),d1
	beq.s noclosefile
	jsr -$24(a6) ;Close	
noclosefile
	move.l DBGFILEHANDLE(a5),d1
	beq.s noclosedbgfile
	jsr -$24(a6) ;Close	
noclosedbgfile

	move.l MEMORY(a5),d0
	beq.s nofreemem
	move.l EXECBASE(a5),a6
	move.l d0,a1
	move.l FILELEN(a5),d0
	jsr -$d2(a6) ;FreeMem
nofreemem
	move.l DBGMEMORY(a5),d0
	beq.s nodbgfreemem
	move.l d0,a1
	move.l DBGFILELEN(a5),d0
	jsr -$d2(a6) ;FreeMem
nodbgfreemem
	
quit2	
	move.l EXECBASE(a5),a6
	move.l DOSBASE(a5),d0
	beq.s nodos
	move.l d0,a1
	jsr -$19e(a6)
nodos

	tst.b OK(a5)
	beq quit

	move.l EXECBASE(a5),a6

	move.l TASK(a5),d0
	lea allocmem+2(pc),a0
	move.l d0,(a0)
	lea freemem+2(pc),a0
	move.l d0,(a0)

	lea allocmem_uae_p+2(pc),a0
	move.l a4,(a0)
	lea freemem_uae_p+2(pc),a0
	move.l a4,(a0)

	lea allocvec_uae_p+2(pc),a0
	move.l a4,(a0)
	lea freevec_uae_p+2(pc),a0
	move.l a4,(a0)
	
	lea trapcode_uae_p+2(pc),a0
	move.l a4,(a0)

	lea exit_uae+2(pc),a0
	move.l a4,(a0)

	lea allocmem(pc),a0
	move.l a0,d0
	move.l a6,a1
	move.w #-$c6,a0
	jsr -$1a4(a6)
	lea allocmem_func+2(pc),a0
	move.l d0,(a0)

	lea freemem(pc),a0
	move.l a0,d0
	move.l a6,a1
	move.w #-$d2,a0
	jsr -$1a4(a6)
	lea freemem_func+2(pc),a0
	move.l d0,(a0)

	lea allocvec(pc),a0
	move.l a0,d0
	move.l a6,a1
	move.w #-$2ac,a0
	jsr -$1a4(a6)
	lea allocvec_func+2(pc),a0
	move.l d0,(a0)

	lea freevec(pc),a0
	move.l a0,d0
	move.l a6,a1
	move.w #-$2b2,a0
	jsr -$1a4(a6)
	lea freevec_func+2(pc),a0
	move.l d0,(a0)

	; swap to new debugmem stack
	move.l NEWSTACK(a5),d0
	lea STACKSWAP(a5),a0
	move.l d0,(a0) ;stk_Lower
	add.l STACKSIZE(a5),d0
	move.l d0,4(a0) ;stk_Upper
	move.l d0,8(a0) ;stk_Pointer
	jsr -$2dc(a6)
	
	move.l STACKFRAME(a5),a0 ;stk_Lower
	move.l STACKSIZE(a5),-(sp)
	pea programexit(pc)
	sub.w #(1+7+8)*4,sp
	move.l sp,a1
	moveq #1+7+8-1,d0
copystack
	move.l (a0)+,(a1)+
	dbf d0,copystack
	
	move.l TASK(a5),a1
	lea 16*4+4(sp),a0
	; point to stack size in stack
	move.l a0,176(a1) ;pr_ReturnAddr
	lea trapcode(pc),a0
	move.l a0,50(a1) ;tc_TrapCode

quit
	movem.l (sp)+,d0-d7/a0-a6
	rts
exit
	moveq #20,d0
	rts

programexit
	addq.l #4,sp ;pop stacksize
	lea data,a5
	move.l d0,d2

	move.l CLI(a5),a0
	move.l CLI_COMMANDNAME(a5),16(a0)
	move.l CLI_MODULE(a5),60(a0)
	move.l TASK(a5),a0
	move.l CLI_ARGUMENTS(a5),204(a0)
	move.l CLI_RETURNADDR(a5),176(a0)
	clr.l 50(a0) ;tc_TrapCode

	move.l EXECBASE(a5),a6
	
	move.l allocmem_func+2(pc),d0
	move.l a6,a1
	move.w #-$c6,a0
	jsr -$1a4(a6)

	move.l freemem_func+2(pc),d0
	move.l a6,a1
	move.w #-$d2,a0
	jsr -$1a4(a6)

	move.l allocvec_func+2(pc),d0
	move.l a6,a1
	move.w #-$2ac,a0
	jsr -$1a4(a6)

	move.l freevec_func+2(pc),d0
	move.l a6,a1
	move.w #-$2b2,a0
	jsr -$1a4(a6)

	move.l #299,d1
exit_uae
	jsr 0.l
	
	lea STACKSWAP(a5),a0
	jsr -$2dc(a6)

	add.w #(1+7+8)*4,sp
	move.l d2,d0
	rts

	; a1 / d0
freemem
	cmp.l #0,276(a6)
	beq.s freemem_uae
freemem_func
	jsr 0.l
	rts
freemem_uae
	move.l #205,d1
	move.l (sp),a0
freemem_uae_p
	jsr 0.l
	tst.l d0
	beq.s freemem_func
	rts

	; d0 / d1
allocmem
	cmp.l #0,276(a6)
	beq.s allocmem_uae
allocmem_func
	jsr 0.l
	rts
allocmem_uae
	move.l d1,a1
	move.l (sp),a0
	move.l #204,d1
allocmem_uae_p
	jsr 0.l
	cmp.w #0,a0
	beq.s allocmem_func
	rts

	; a1
freevec
	cmp.l #0,276(a6)
	beq.s freevec_uae
freevec_func
	jsr 0.l
	rts
freevec_uae
	move.l #207,d1
	move.l (sp),a0
freevec_uae_p
	jsr 0.l
	tst.l d0
	beq.s freevec_func
	rts


	; d0 / d1	
allocvec
	cmp.l #0,276(a6)
	beq.s allocvec_uae
allocvec_func
	jsr 0.l
	rts
allocvec_uae
	move.l d1,a1
	move.l (sp),a0
	move.l #206,d1
allocvec_uae_p
	jsr 0.l
	cmp.w #0,a0
	beq.s allocvec_func
	rts

trapcode
	movem.l d0-d1/a0-a1,-(sp)
	lea 4*4(sp),a0
	move.l #210,d1
trapcode_uae_p
	jsr 0.l
	movem.l (sp)+,d0-d1/a0-a1
	addq.l #4,sp
	rte

dos
	dc.b "dos.library",0
uaeres
	dc.b "uae.resource",0
funcname
	dc.b "misc_funcs",0
dbgext
	dc.b "dbg",0
	even

	section 2,bss

data
	ds.b DATA_SIZE


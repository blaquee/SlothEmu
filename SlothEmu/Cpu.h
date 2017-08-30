//**********************************************************************
// Class Definition File: Cpu.h
// Author: glindor
// Date: Aug 22, 2017
//
// Abstract:
//
//   This file contains the class definition for class Cpu.
//
// Copyright (c) 2017, glindor.
//
//**********************************************************************

#ifndef CPU_H
#define CPU_H

#include "pluginmain.h"
//======================================================================
// Class Definition
//======================================================================

class Cpu
{
private:

	duint CAX;
	duint CCX;
	duint CDX;
	duint CBX;
	duint CDI;
	duint CBP;
	duint CSP;
	duint R8;
	duint R9;
	duint R10;
	duint R11;
	duint R12;
	duint R13;
	duint R14;
	duint R15;
	duint CIP;
	duint ELFAGS;
	duint CF;
	duint PF;
	duint AF;
	duint ZF;
	duint SF;
	duint TF;
	duint IF;
	duint DF;
	duint OF;
	duint GS;
	duint FS;
	duint ES;
	duint DS;
	duint CS;
	duint SS;
	duint LastError;
	duint DR0;
	duint DR1;
	duint DR2;
	duint DR3;
	duint DR4;
	duint DR5;
	duint DR6;
	duint DR7;


public:

	Cpu();

	Cpu(const Cpu & that);

	~Cpu();

	Cpu & operator =(const Cpu & that);

	void Copy(const Cpu & that);

	duint getCAX() const;

	void setCAX(const duint & the_value);

	duint getCCX() const;

	void setCCX(const duint & the_value);

	duint getCDX() const;

	void setCDX(const duint & the_value);

	duint getCBX() const;

	void setCBX(const duint & the_value);

	duint getCDI() const;

	void setCDI(const duint & the_value);

	duint getCBP() const;

	void setCBP(const duint & the_value);

	duint getCSP() const;

	void setCSP(const duint & the_value);

	duint getR8() const;

	void setR8(const duint & the_value);

	duint getR9() const;

	void setR9(const duint & the_value);

	duint getR10() const;

	void setR10(const duint & the_value);

	duint getR11() const;

	void setR11(const duint & the_value);

	duint getR12() const;

	void setR12(const duint & the_value);

	duint getR13() const;

	void setR13(const duint & the_value);

	duint getR14() const;

	void setR14(const duint & the_value);

	duint getR15() const;

	void setR15(const duint & the_value);

	duint getCIP() const;

	void setCIP(const duint & the_value);

	duint getEFLAGS() const;

	void setEFLAGS(const duint & the_value);

	duint getCF() const;

	void setCF(const duint & the_value);

	duint getPF() const;

	void setPF(const duint & the_value);

	duint getAF() const;

	void setAF(const duint & the_value);

	duint getZF() const;

	void setZF(const duint & the_value);

	duint getSF() const;

	void setSF(const duint & the_value);

	duint getTF() const;

	void setTF(const duint & the_value);

	duint getIF() const;

	void setIF(const duint & the_value);

	duint getDF() const;

	void setDF(const duint & the_value);

	duint getOF() const;

	void setOF(const duint & the_value);

	duint getGS() const;

	void setGS(const duint & the_value);

	duint getFS() const;

	void setFS(const duint & the_value);

	duint getES() const;

	void setES(const duint & the_value);

	duint getDS() const;

	void setDS(const duint & the_value);

	duint getCS() const;

	void setCS(const duint & the_value);

	duint getSS() const;

	void setSS(const duint & the_value);

	duint getLastError() const;

	void setLastError(const duint & the_value);

	duint getDR0() const;

	void setDR0(const duint & the_value);

	duint getDR1() const;

	void setDR1(const duint & the_value);

	duint getDR2() const;

	void setDR2(const duint & the_value);

	duint getDR3() const;

	void setDR3(const duint & the_value);

	duint getDR4() const;

	void setDR4(const duint & the_value);

	duint getDR5() const;

	void setDR5(const duint & the_value);

	duint getDR6() const;

	void setDR6(const duint & the_value);

	duint getDR7() const;

	void setDR7(const duint & the_value);
};

#endif

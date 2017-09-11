//**********************************************************************
// Class Definition File: Cpu.h
// Author: glindor
//
// Abstract:
//
//   This file contains the class definition for class Cpu.
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
	duint CSI;
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

	Cpu & operator =(const Cpu & that) = default;

	void Copy(const Cpu & that);

	duint getCAX() const;

	void setCAX(const duint & value);

	duint getCCX() const;

	void setCCX(const duint & value);

	duint getCDX() const;

	void setCDX(const duint & value);

	duint getCBX() const;

	void setCBX(const duint & value);

	duint getCDI() const;

	void setCDI(const duint & value);

	duint getCSI() const;

	void setCSI(const duint & value);

	duint getCBP() const;

	void setCBP(const duint & value);

	duint getCSP() const;

	void setCSP(const duint & value);

	duint getR8() const;

	void setR8(const duint & value);

	duint getR9() const;

	void setR9(const duint & value);

	duint getR10() const;

	void setR10(const duint & value);

	duint getR11() const;

	void setR11(const duint & value);

	duint getR12() const;

	void setR12(const duint & value);

	duint getR13() const;

	void setR13(const duint & value);

	duint getR14() const;

	void setR14(const duint & value);

	duint getR15() const;

	void setR15(const duint & value);

	duint getCIP() const;

	void setCIP(const duint & value);

	duint getEFLAGS() const;

	void setEFLAGS(const duint & value);

	duint getCF() const;

	void setCF(const duint & value);

	duint getPF() const;

	void setPF(const duint & value);

	duint getAF() const;

	void setAF(const duint & value);

	duint getZF() const;

	void setZF(const duint & value);

	duint getSF() const;

	void setSF(const duint & value);

	duint getTF() const;

	void setTF(const duint & value);

	duint getIF() const;

	void setIF(const duint & value);

	duint getDF() const;

	void setDF(const duint & value);

	duint getOF() const;

	void setOF(const duint & value);

    duint getGS() const;

	void setGS(const duint & value);

    duint getFS() const;

	void setFS(const duint & value);

    duint getES() const;

	void setES(const duint & value);

    duint getDS() const;

	void setDS(const duint & value);

    duint getCS() const;

	void setCS(const duint & value);

    duint getSS() const;

	void setSS(const duint & value);

	duint getLastError() const;

	void setLastError(const duint & value);

	duint getDR0() const;

	void setDR0(const duint & value);

	duint getDR1() const;

	void setDR1(const duint & value);

	duint getDR2() const;

	void setDR2(const duint & value);

	duint getDR3() const;

	void setDR3(const duint & value);

	duint getDR4() const;

	void setDR4(const duint & value);

	duint getDR5() const;

	void setDR5(const duint & value);

	duint getDR6() const;

	void setDR6(const duint & value);

	duint getDR7() const;

	void setDR7(const duint & value);
};

#endif

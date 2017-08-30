//**********************************************************************
// Class Implementation File: Cpu.cpp
// Author: glindor
// Date: Aug 22, 2017
//
// Abstract:
//
//   This file contains the class implementation for class Cpu.
//
// Copyright (c) 2017, glindor.
//
//**********************************************************************

#include "Cpu.h"

Cpu::Cpu()
	: CAX(0)
	, CCX(0)
	, CDX(0)
	, CBX(0)
	, CDI(0)
	, CBP(0)
	, CSP(0)
	, R8(0)
	, R9(0)
	, R10(0)
	, R11(0)
	, R12(0)
	, R13(0)
	, R14(0)
	, R15(0)
	, CIP(0)
	, ELFAGS(0)
	, CF(0)
	, PF(0)
	, AF(0)
	, ZF(0)
	, SF(0)
	, TF(0)
	, IF(0)
	, DF(0)
	, OF(0)
	, GS(0)
	, FS(0)
	, ES(0)
	, DS(0)
	, CS(0)
	, SS(0)
	, LastError(0)
	, DR0(0)
	, DR1(0)
	, DR2(0)
	, DR3(0)
	, DR4(0)
	, DR5(0)
	, DR6(0)
	, DR7(0)
{
}

//======================================================================
//  Copy Constructor: Cpu::Cpu
//
//  Abstract:
//
//      This copy constructor copies the passed class instance to this class instance.
//======================================================================

Cpu::Cpu(const Cpu & that)
{
	Copy(that);
}

//======================================================================
//  Destructor: Cpu::~Cpu
//======================================================================

Cpu::~Cpu()
{
}

//======================================================================
//  Operator: Cpu::operator =
//
//  Abstract:
//
//      This equals operator copies the passed class instance to this class instance
//      and returns this class instance.
//======================================================================

Cpu & Cpu::operator =(const Cpu & that)
{
	// TODO: Consider testing for inequality by value.
	//if (*this != *that)
	if (this != &that)
	{
		Copy(that);
	}

	return *this;
}

//======================================================================
//  Member Function: Cpu::Copy
//
//  Abstract:
//
//      This method copies the passed class instance.
//======================================================================

void Cpu::Copy(const Cpu & that)
{
	// xxxxxx - The code below does a shallow copy of the class data members.
	// If any data members are pointers and a deep copy is needed then this code
	// should be changed.
	CAX = that.CAX;
	CCX = that.CCX;
	CDX = that.CDX;
	CBX = that.CBX;
	CDI = that.CDI;
	CBP = that.CBP;
	CSP = that.CSP;
	R8 = that.R8;
	R9 = that.R9;
	R10 = that.R10;
	R11 = that.R11;
	R12 = that.R12;
	R13 = that.R13;
	R14 = that.R14;
	R15 = that.R15;
	CIP = that.CIP;
	ELFAGS = that.ELFAGS;
	CF = that.CF;
	PF = that.PF;
	AF = that.AF;
	ZF = that.ZF;
	SF = that.SF;
	TF = that.TF;
	IF = that.IF;
	DF = that.DF;
	OF = that.OF;
	GS = that.GS;
	FS = that.FS;
	ES = that.ES;
	DS = that.DS;
	CS = that.CS;
	SS = that.SS;
	LastError = that.LastError;
	DR0 = that.DR0;
	DR1 = that.DR1;
	DR2 = that.DR2;
	DR3 = that.DR3;
	DR4 = that.DR4;
	DR5 = that.DR5;
	DR6 = that.DR6;
	DR7 = that.DR7;
}

//======================================================================
//  Member Function: Cpu::CAX
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getCAX() const
{
	return CAX;
}

//======================================================================
//  Member Function: Cpu::setCAX
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setCAX(const duint & the_value)
{
	CAX = the_value;
}

//======================================================================
//  Member Function: Cpu::CCX
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getCCX() const
{
	return CCX;
}

//======================================================================
//  Member Function: Cpu::setCCX
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setCCX(const duint & the_value)
{
	CCX = the_value;
}

//======================================================================
//  Member Function: Cpu::CDX
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getCDX() const
{
	return CDX;
}

//======================================================================
//  Member Function: Cpu::setCDX
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setCDX(const duint & the_value)
{
	CDX = the_value;
}

//======================================================================
//  Member Function: Cpu::CBX
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getCBX() const
{
	return CBX;
}

//======================================================================
//  Member Function: Cpu::setCBX
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setCBX(const duint & the_value)
{
	CBX = the_value;
}

//======================================================================
//  Member Function: Cpu::CDI
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getCDI() const
{
	return CDI;
}

//======================================================================
//  Member Function: Cpu::setCDI
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setCDI(const duint & the_value)
{
	CDI = the_value;
}

//======================================================================
//  Member Function: Cpu::CBP
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getCBP() const
{
	return CBP;
}

//======================================================================
//  Member Function: Cpu::setCBP
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setCBP(const duint & the_value)
{
	CBP = the_value;
}

//======================================================================
//  Member Function: Cpu::CSP
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getCSP() const
{
	return CSP;
}

//======================================================================
//  Member Function: Cpu::setCSP
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setCSP(const duint & the_value)
{
	CSP = the_value;
}

//======================================================================
//  Member Function: Cpu::R8
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getR8() const
{
	return R8;
}

//======================================================================
//  Member Function: Cpu::setR8
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setR8(const duint & the_value)
{
	R8 = the_value;
}

//======================================================================
//  Member Function: Cpu::R9
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getR9() const
{
	return R9;
}

//======================================================================
//  Member Function: Cpu::setR9
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setR9(const duint & the_value)
{
	R9 = the_value;
}

//======================================================================
//  Member Function: Cpu::R10
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getR10() const
{
	return R10;
}

//======================================================================
//  Member Function: Cpu::setR10
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setR10(const duint & the_value)
{
	R10 = the_value;
}

//======================================================================
//  Member Function: Cpu::R11
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getR11() const
{
	return R11;
}

//======================================================================
//  Member Function: Cpu::setR11
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setR11(const duint & the_value)
{
	R11 = the_value;
}

//======================================================================
//  Member Function: Cpu::R12
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getR12() const
{
	return R12;
}

//======================================================================
//  Member Function: Cpu::setR12
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setR12(const duint & the_value)
{
	R12 = the_value;
}

//======================================================================
//  Member Function: Cpu::R13
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getR13() const
{
	return R13;
}

//======================================================================
//  Member Function: Cpu::setR13
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setR13(const duint & the_value)
{
	R13 = the_value;
}

//======================================================================
//  Member Function: Cpu::R14
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getR14() const
{
	return R14;
}

//======================================================================
//  Member Function: Cpu::setR14
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setR14(const duint & the_value)
{
	R14 = the_value;
}

//======================================================================
//  Member Function: Cpu::R15
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getR15() const
{
	return R15;
}

//======================================================================
//  Member Function: Cpu::setR15
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setR15(const duint & the_value)
{
	R15 = the_value;
}

//======================================================================
//  Member Function: Cpu::CIP
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getCIP() const
{
	return CIP;
}

//======================================================================
//  Member Function: Cpu::setCIP
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setCIP(const duint & the_value)
{
	CIP = the_value;
}

//======================================================================
//  Member Function: Cpu::EFLAGS
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getEFLAGS() const
{
	return ELFAGS;
}

//======================================================================
//  Member Function: Cpu::setEFLAGS
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setEFLAGS(const duint & the_value)
{
	ELFAGS = the_value;
}

//======================================================================
//  Member Function: Cpu::CF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getCF() const
{
	return CF;
}

//======================================================================
//  Member Function: Cpu::setCF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setCF(const duint & the_value)
{
	CF = the_value;
}

//======================================================================
//  Member Function: Cpu::PF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getPF() const
{
	return PF;
}

//======================================================================
//  Member Function: Cpu::setPF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setPF(const duint & the_value)
{
	PF = the_value;
}

//======================================================================
//  Member Function: Cpu::AF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getAF() const
{
	return AF;
}

//======================================================================
//  Member Function: Cpu::setAF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setAF(const duint & the_value)
{
	AF = the_value;
}

//======================================================================
//  Member Function: Cpu::ZF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getZF() const
{
	return ZF;
}

//======================================================================
//  Member Function: Cpu::setZF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setZF(const duint & the_value)
{
	ZF = the_value;
}

//======================================================================
//  Member Function: Cpu::SF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getSF() const
{
	return SF;
}

//======================================================================
//  Member Function: Cpu::setSF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setSF(const duint & the_value)
{
	SF = the_value;
}

//======================================================================
//  Member Function: Cpu::TF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getTF() const
{
	return TF;
}

//======================================================================
//  Member Function: Cpu::setTF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setTF(const duint & the_value)
{
	TF = the_value;
}

//======================================================================
//  Member Function: Cpu::IF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getIF() const
{
	return IF;
}

//======================================================================
//  Member Function: Cpu::setIF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setIF(const duint & the_value)
{
	IF = the_value;
}

//======================================================================
//  Member Function: Cpu::DF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getDF() const
{
	return DF;
}

//======================================================================
//  Member Function: Cpu::setDF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setDF(const duint & the_value)
{
	DF = the_value;
}

//======================================================================
//  Member Function: Cpu::OF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getOF() const
{
	return OF;
}

//======================================================================
//  Member Function: Cpu::setOF
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setOF(const duint & the_value)
{
	OF = the_value;
}

//======================================================================
//  Member Function: Cpu::GS
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getGS() const
{
	return GS;
}

//======================================================================
//  Member Function: Cpu::setGS
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setGS(const duint & the_value)
{
	GS = the_value;
}

//======================================================================
//  Member Function: Cpu::FS
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getFS() const
{
	return FS;
}

//======================================================================
//  Member Function: Cpu::setFS
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setFS(const duint & the_value)
{
	FS = the_value;
}

//======================================================================
//  Member Function: Cpu::ES
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getES() const
{
	return ES;
}

//======================================================================
//  Member Function: Cpu::setES
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setES(const duint & the_value)
{
	ES = the_value;
}

//======================================================================
//  Member Function: Cpu::DS
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getDS() const
{
	return DS;
}

//======================================================================
//  Member Function: Cpu::setDS
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setDS(const duint & the_value)
{
	DS = the_value;
}

//======================================================================
//  Member Function: Cpu::CS
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getCS() const
{
	return CS;
}

//======================================================================
//  Member Function: Cpu::setCS
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setCS(const duint & the_value)
{
	CS = the_value;
}

//======================================================================
//  Member Function: Cpu::SS
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getSS() const
{
	return SS;
}

//======================================================================
//  Member Function: Cpu::setSS
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setSS(const duint & the_value)
{
	SS = the_value;
}

//======================================================================
//  Member Function: Cpu::LastError
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getLastError() const
{
	return LastError;
}

//======================================================================
//  Member Function: Cpu::setLastError
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setLastError(const duint & the_value)
{
	LastError = the_value;
}

//======================================================================
//  Member Function: Cpu::DR0
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getDR0() const
{
	return DR0;
}

//======================================================================
//  Member Function: Cpu::setDR0
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setDR0(const duint & the_value)
{
	DR0 = the_value;
}

//======================================================================
//  Member Function: Cpu::DR1
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getDR1() const
{
	return DR1;
}

//======================================================================
//  Member Function: Cpu::setDR1
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setDR1(const duint & the_value)
{
	DR1 = the_value;
}

//======================================================================
//  Member Function: Cpu::DR2
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getDR2() const
{
	return DR2;
}

//======================================================================
//  Member Function: Cpu::setDR2
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setDR2(const duint & the_value)
{
	DR2 = the_value;
}

//======================================================================
//  Member Function: Cpu::DR3
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getDR3() const
{
	return DR3;
}

//======================================================================
//  Member Function: Cpu::setDR3
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setDR3(const duint & the_value)
{
	DR3 = the_value;
}

//======================================================================
//  Member Function: Cpu::DR4
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getDR4() const
{
	return DR4;
}

//======================================================================
//  Member Function: Cpu::setDR4
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setDR4(const duint & the_value)
{
	DR4 = the_value;
}

//======================================================================
//  Member Function: Cpu::DR5
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getDR5() const
{
	return DR5;
}

//======================================================================
//  Member Function: Cpu::setDR5
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setDR5(const duint & the_value)
{
	DR5 = the_value;
}

//======================================================================
//  Member Function: Cpu::DR6
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getDR6() const
{
	return DR6;
}

//======================================================================
//  Member Function: Cpu::setDR6
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setDR6(const duint & the_value)
{
	DR6 = the_value;
}

//======================================================================
//  Member Function: Cpu::DR7
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

duint Cpu::getDR7() const
{
	return DR7;
}

//======================================================================
//  Member Function: Cpu::setDR7
//
//  Abstract:
//
//      This method xxxxxx
//======================================================================

void Cpu::setDR7(const duint & the_value)
{
	DR7 = the_value;
}

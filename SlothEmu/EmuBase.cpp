#include "EmuBase.h"

bool EmuBase::setEmuAddr(duint begin, duint end)
{
	if (end < begin)
		return false;
	if ((end - begin) < 1)
		return false;

	beginEmuAddr = begin;
	endEmuAddr = end;
	return true;
}

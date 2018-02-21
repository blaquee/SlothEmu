#ifndef _H_EMUBASE_
#define _H_EMUBASE_

#include "plugin.h"
#include "unicorn/unicorn.h"
#include "capstone_wrapper/capstone_wrapper.h"
#include "Cpu.h"
#include "fmt/format.h"

#include <vector>
#include <map>
#include <string>

using namespace std;

class EmuBase
{
private:
    uc_engine* uc;
	string logmsg;

	duint beginEmuAddr;
	duint endEmuAddr;

	bool emuStarted;


public:
	EmuBase() {}
	~EmuBase() = default;

	bool setEmuAddr(duint begin, duint end);


};
#endif // 

#ifndef _H_EMUBASE_
#define _H_EMUBASE_

#include "plugin.h"
#include "unicorn/unicorn.h"
#include "capstone_wrapper/capstone_wrapper.h"
#include "Cpu.h"

#include <vector>
#include <map>

class EmuBase
{
private:
    uc_engine* uc;
public:
    EmuBase()
};
#endif // 

#pragma once

#include "unicorn/unicorn.h"
#include "defines.h"


// How we want to emulate
enum STEPMODE
{
    step_single_step,
    step_emu_all,
    step_stop_ret,
    step_max
};

bool InitEmuEngine();
bool SetupEnvironment(uc_engine* engine);
bool SetupDescriptorTable(uc_engine* engine);
bool SetupContext(uc_engine* engine);

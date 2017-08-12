#include "emu.h"
#include "plugin.h"

bool g_EngineInit;
uc_engine* g_engine = NULL;


namespace engine
{
    class EmuEngine
    {
    private:
        uc_engine* engine = nullptr;

        EmuEngine::EmuEngine(){}

    };
}
bool InitEmuEngine()
{
    //initialize the engine 
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &g_engine);
    if(err != UC_ERR_OK)
    {
        _plugin_logputs("Failed to load emu engine");
        return false;
    }
    return true;
}

bool SetupEnvironment(uc_engine* engine)
{
    return false;
}

bool SetupDescriptorTable(uc_engine* engine)
{
    return false;
}

bool SetupContext(uc_engine* engine)
{
    return false;
}

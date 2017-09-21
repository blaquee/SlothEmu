#include <vector>
#include "EmuHooks.h"

std::vector<MAPPER> gMappedMemoryInfo;

void EmuHookCode(uc_engine* uc, duint addr, size_t size, void* userdata)
{
    duint curRip;
    uc_reg_read(uc, UC_X86_REG_RIP, &curRip);
    char msg[256];
    sprintf_s(msg,"executing instruction at 0x%X, size: %u", addr, size);
    GuiAddLogMessage(msg);
    //EmuDumpRegs(uc);
    // callback
    // OnCodeExecute();
    return;
}

// return false to stop emulation
bool EmuHookMemInvalid(uc_engine* uc, uc_mem_type type, duint address, int size, int64_t value, void* userdata)
{
    MAPPER lMemMap;
    unsigned char mem[PAGE_SIZE];
    uc_err err;
    switch (type)
    {
    default:
        return false;
    case UC_MEM_WRITE_UNMAPPED:
        GuiAddLogMessage("Unmapped Memory write reached");
        return false;
    case UC_MEM_READ_UNMAPPED:
        GuiAddLogMessage("Unmapped memory read reached");
        // Lets map the memory
        //TODO: Goes in a callback that ensures we're not mapping overlapped memory
        if (DbgMemIsValidReadPtr(address))
        {
            //Address is accessible. Map one page size at a time and save it
            if (DbgMemRead(address, mem, PAGE_SIZE))
            {
                // map the memory
                err = uc_mem_map(uc, address, PAGE_SIZE, UC_PROT_ALL);
                if (err != UC_ERR_OK)
                {
                    GuiAddLogMessage("Something went wrong mapping the memory");
                    return false;
                }
                err = uc_mem_write(uc, address, mem, PAGE_SIZE);
                if (err != UC_ERR_OK)
                {
                    GuiAddLogMessage("Error writing to the mapped memory");
                    return false;
                }
                //store info
                lMemMap.addr = address;
                lMemMap.len = PAGE_SIZE;
                lMemMap.mapped = true;
                gMappedMemoryInfo.push_back(lMemMap);
            }
            return true;
        }
        GuiAddLogMessage("Invalid Memory read");
        return false;
    case UC_MEM_FETCH_UNMAPPED:
        GuiAddLogMessage("Unmapped fetched memory reached");
        return false;
    }
    return true;
}

void EmuHookMem(uc_engine* uc, uc_mem_type type, duint address, int size, int64_t value, void* userdata)
{
    switch (type)
    {
    default:break;
    case UC_MEM_READ:
        _plugin_logprintf("Reading Memory at: %X size: %u", address, size);
        break;
    case UC_MEM_WRITE:
        _plugin_logprintf("Writing to Memory at: %X, value: %X, size: %u", address, value, size);
        break;
    }
    return;
}


#include "plugin.h"
#include "emu.h"
#include "unicorn\unicorn.h"


extern bool g_EngineInit;
extern uc_engine* g_engine;

enum
{
    MENU_TEST,
    MENU_DISASM_ADLER32
};



bool ReadSelection(int hWindow)
{
    if(!DbgIsDebugging())
    {
        _plugin_logputs("[" PLUGIN_NAME "] Not Debugging");
        return false;
    }

    //Get the Selection Data
    SELECTIONDATA sel;
    GuiSelectionGet(hWindow, &sel);
    duint lenSelection = sel.end - sel.start + 1;
    unsigned char* data = new unsigned char[lenSelection];

    // Read the memory data
    if(DbgMemRead(sel.start, data, lenSelection))
    {
        if(data)
        {
			// if emulator is active, pass data to be emulated
			if (g_EngineInit && g_engine)
			{
				if (!PrepareDataToEmulate(data, lenSelection, sel.start, false))
				{
					_plugin_logputs("Failed to emulate the data");
					return false;
				}
			}
			else
			{
				_plugin_logputs("Emulator not initialized");
				return false;
			}
        }
    }
	return true;
}


static bool cbTestCommand(int argc, char* argv[])
{
    _plugin_logputs("[" PLUGIN_NAME "] Test command!");
    char line[GUI_MAX_LINE_SIZE] = "";
    if(!GuiGetLineWindow("test", line))
        _plugin_logputs("[" PLUGIN_NAME "] Cancel pressed!");
    else
        _plugin_logprintf("[" PLUGIN_NAME "] Line: \"%s\"\n", line);
    return true;
}

PLUG_EXPORT void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG* info)
{
    _plugin_logprintf("[" PLUGIN_NAME "] Debugging of %s started!\n", info->szFileName);
}

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
    _plugin_logputs("[" PLUGIN_NAME "] Debugging stopped!");
}

PLUG_EXPORT void CBEXCEPTION(CBTYPE cbType, PLUG_CB_EXCEPTION* info)
{
    _plugin_logprintf("[" PLUGIN_NAME "] ExceptionRecord.ExceptionCode: %08X\n", info->Exception->ExceptionRecord.ExceptionCode);
}

PLUG_EXPORT void CBDEBUGEVENT(CBTYPE cbType, PLUG_CB_DEBUGEVENT* info)
{
    if(info->DebugEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
    {
        _plugin_logprintf("[" PLUGIN_NAME "] DebugEvent->EXCEPTION_DEBUG_EVENT->%.8X\n", info->DebugEvent->u.Exception.ExceptionRecord.ExceptionCode);
    }
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch(info->hEntry)
    {
    case MENU_DISASM_ADLER32:
        ReadSelection(GUI_DISASSEMBLY);
        break;

    default:
        break;
    }
}

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    if(!_plugin_registercommand(pluginHandle, PLUGIN_NAME, cbTestCommand, false))
        _plugin_logputs("[" PLUGIN_NAME "] Error registering the \"" PLUGIN_NAME "\" command!");

	if (!InitEmuEngine())
	{
		_plugin_logputs("Emulation Engine failed to start, failing plugin load");
		return false;
	}
    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here (clearing menus optional).
bool pluginStop()
{
    _plugin_unregistercommand(pluginHandle, PLUGIN_NAME);
    _plugin_menuclear(hMenu);
    _plugin_menuclear(hMenuDisasm);
    _plugin_menuclear(hMenuDump);
    _plugin_menuclear(hMenuStack);
    return true;
}

//Do GUI/Menu related things here.
void pluginSetup()
{
    //_plugin_menuaddentry(hMenu, MENU_TEST, "&Menu Test");
    _plugin_menuaddentry(hMenuDisasm, MENU_DISASM_ADLER32, "&Emulate Selection");
    //_plugin_menuaddentry(hMenuDump, MENU_DUMP_ADLER32, "&Adler32 Selection");
    //_plugin_menuaddentry(hMenuStack, MENU_STACK_ADLER32, "&Adler32 Selection");
}

#include "capstone_wrapper.h"
#include <windows.h>

csh Capstone::mHandle = 0;
bool Capstone::mInitialized = false;

static void customMnem(csh handle, x86_insn mnem, const char* alias)
{
    cs_opt_mnem om = { mnem, (char*)alias };
    cs_option(handle, CS_OPT_MNEMONIC, (size_t)&om);
}

void Capstone::GlobalInitialize()
{
    if(!mInitialized)
    {
        mInitialized = true;
#ifdef _WIN64
        cs_open(CS_ARCH_X86, CS_MODE_64, &mHandle);
#else //x86
        cs_open(CS_ARCH_X86, CS_MODE_32, &mHandle);
#endif //_WIN64
        cs_option(mHandle, CS_OPT_DETAIL, CS_OPT_ON);
        customMnem(mHandle, X86_INS_PUSHAL, "pushad");
        customMnem(mHandle, X86_INS_POPAL, "popad");
    }
}

void Capstone::GlobalFinalize()
{
    if(mHandle) //close handle
        cs_close(&mHandle);
    mInitialized = false;
}

Capstone::Capstone()
{
    GlobalInitialize();
    mInstr = cs_malloc(mHandle);
    mSuccess = false;
}

Capstone::Capstone(const Capstone & capstone)
    : mInstr(cs_malloc(mHandle)),
      mSuccess(false)
{
}

Capstone::~Capstone()
{
    if(mInstr) //free last disassembled instruction
        cs_free(mInstr, 1);
}

bool Capstone::Disassemble(size_t addr, const unsigned char data[MAX_DISASM_BUFFER])
{
    return Disassemble(addr, data, MAX_DISASM_BUFFER);
}

bool Capstone::Disassemble(size_t addr, const unsigned char* data, int size)
{
    if(!data || !size)
        return false;

    size_t codeSize = size;
    uint64_t addr64 = addr;

    return (mSuccess = cs_disasm_iter(mHandle, &data, &codeSize, &addr64, mInstr));
}

bool Capstone::DisassembleSafe(size_t addr, const unsigned char* data, int size)
{
    unsigned char dataSafe[MAX_DISASM_BUFFER];
    memset(dataSafe, 0, sizeof(dataSafe));
    memcpy(dataSafe, data, min(MAX_DISASM_BUFFER, size_t(size)));
    return Disassemble(addr, dataSafe);
}

const cs_insn* Capstone::GetInstr() const
{
    if(!Success())
        return nullptr;
    return mInstr;
}

bool Capstone::Success() const
{
    return mSuccess;
}

const char* Capstone::RegName(x86_reg reg) const
{
    switch(reg)
    {
    case X86_REG_ST0:
        return "st(0)";
    case X86_REG_ST1:
        return "st(1)";
    case X86_REG_ST2:
        return "st(2)";
    case X86_REG_ST3:
        return "st(3)";
    case X86_REG_ST4:
        return "st(4)";
    case X86_REG_ST5:
        return "st(5)";
    case X86_REG_ST6:
        return "st(6)";
    case X86_REG_ST7:
        return "st(7)";
    default:
        return cs_reg_name(mHandle, reg);
    }
}

bool Capstone::InGroup(cs_group_type group) const
{
    if(!Success())
        return false;
    if(group == CS_GRP_PRIVILEGE)
    {
        auto id = GetId();
        // I/O instructions
        if(id == X86_INS_OUT || id == X86_INS_OUTSB || id == X86_INS_OUTSD || id == X86_INS_OUTSW
                || id == X86_INS_IN || id == X86_INS_INSB || id == X86_INS_INSD || id == X86_INS_INSW
                // system instructions
                || id == X86_INS_RDMSR || id == X86_INS_SMSW)
            return true;
    }
    return cs_insn_group(mHandle, mInstr, group);
}

std::string Capstone::OperandText(int opindex) const
{
    if(!Success() || opindex >= mInstr->detail->x86.op_count)
        return "";
    const auto & op = mInstr->detail->x86.operands[opindex];
    std::string result;
    char temp[32] = "";
    switch(op.type)
    {
    case X86_OP_REG:
    {
        result = RegName(x86_reg(op.reg));
    }
    break;

    case X86_OP_IMM:
    {
        sprintf_s(temp, "%llX", op.imm);
        result = temp;
    }
    break;

    case X86_OP_MEM:
    {
        const auto & mem = op.mem;
        if(op.mem.base == X86_REG_RIP) //rip-relative
        {
            sprintf_s(temp, "%llX", Address() + op.mem.disp + Size());
            result += temp;
        }
        else //normal
        {
            bool prependPlus = false;
            if(mem.base)
            {
                result += RegName(x86_reg(mem.base));
                prependPlus = true;
            }
            if(mem.index)
            {
                if(prependPlus)
                    result += "+";
                result += RegName(x86_reg(mem.index));
                sprintf_s(temp, "*%X", mem.scale);
                result += temp;
                prependPlus = true;
            }
            if(mem.disp)
            {
                char operatorText = '+';
                if(mem.disp < 0)
                {
                    operatorText = '-';
                    sprintf_s(temp, "%llX", mem.disp * -1);
                }
                else
                    sprintf_s(temp, "%llX", mem.disp);
                if(prependPlus)
                    result += operatorText;
                result += temp;
            }
            if(!mem.disp && !mem.base && !mem.index)
                result += '0';
        }
    }
    break;

    case X86_OP_INVALID:
    {
    }
    break;
    }
    return result;
}

int Capstone::Size() const
{
    if(!Success())
        return 1;
    return GetInstr()->size;
}

size_t Capstone::Address() const
{
    if(!Success())
        return 0;
    return size_t(GetInstr()->address);
}

const cs_x86 & Capstone::x86() const
{
    if(!Success())
        DebugBreak();
    return GetInstr()->detail->x86;
}

bool Capstone::IsFilling() const
{
    if(!Success())
        return false;
    switch(GetId())
    {
    case X86_INS_NOP:
    case X86_INS_INT3:
        return true;
    default:
        return false;
    }
}

bool Capstone::IsLoop() const
{
    if(!Success())
        return false;
    switch(GetId())
    {
    case X86_INS_LOOP:
    case X86_INS_LOOPE:
    case X86_INS_LOOPNE:
        return true;
    default:
        return false;
    }
}

x86_insn Capstone::GetId() const
{
    if(!Success())
        DebugBreak();
    return x86_insn(mInstr->id);
}

std::string Capstone::InstructionText(bool replaceRipRelative) const
{
    if(!Success())
        return "???";
    std::string result = Mnemonic();
    if(OpCount())
    {
        result += " ";
        result += mInstr->op_str;
    }
#ifdef _WIN64
    if(replaceRipRelative)
    {
        //replace [rip +/- 0x?] with the actual address
        bool ripPlus = true;
        auto found = result.find("[rip + ");
        if(found == std::string::npos)
        {
            ripPlus = false;
            found = result.find("[rip - ");
        }
        if(found != std::string::npos)
        {
            auto wVA = Address();
            auto end = result.find("]", found);
            auto ripStr = result.substr(found + 1, end - found - 1);
            uint64_t offset;
            sscanf_s(ripStr.substr(ripStr.rfind(' ') + 1).c_str(), "%llX", &offset);
            auto dest = ripPlus ? (wVA + offset + Size()) : (wVA - offset + Size());
            char buf[20];
            sprintf_s(buf, "0x%llx", dest);
            result.replace(found + 1, ripStr.length(), buf);
        }
    }
#endif //_WIN64
    return result;
}

int Capstone::OpCount() const
{
    if(!Success())
        return 0;
    return x86().op_count;
}

const cs_x86_op & Capstone::operator[](int index) const
{
    if(!Success() || index < 0 || index >= OpCount())
        DebugBreak();
    return x86().operands[index];
}

static bool isSafe64NopRegOp(const cs_x86_op & op)
{
    if(op.type != X86_OP_REG)
        return true; //a non-register is safe
#ifdef _WIN64
    switch(op.reg)
    {
    case X86_REG_EAX:
    case X86_REG_EBX:
    case X86_REG_ECX:
    case X86_REG_EDX:
    case X86_REG_EBP:
    case X86_REG_ESP:
    case X86_REG_ESI:
    case X86_REG_EDI:
        return false; //32 bit register modifications clear the high part of the 64 bit register
    default:
        return true; //all other registers are safe
    }
#else
    return true;
#endif //_WIN64
}

bool Capstone::IsNop() const
{
    if(!Success())
        return false;
    const auto & ops = x86().operands;
    cs_x86_op op;
    switch(GetId())
    {
    case X86_INS_NOP:
    case X86_INS_PAUSE:
    case X86_INS_FNOP:
        // nop
        return true;
    case X86_INS_MOV:
    case X86_INS_CMOVA:
    case X86_INS_CMOVAE:
    case X86_INS_CMOVB:
    case X86_INS_CMOVBE:
    case X86_INS_CMOVE:
    case X86_INS_CMOVNE:
    case X86_INS_CMOVG:
    case X86_INS_CMOVGE:
    case X86_INS_CMOVL:
    case X86_INS_CMOVLE:
    case X86_INS_CMOVO:
    case X86_INS_CMOVNO:
    case X86_INS_CMOVP:
    case X86_INS_CMOVNP:
    case X86_INS_CMOVS:
    case X86_INS_CMOVNS:
    case X86_INS_MOVAPS:
    case X86_INS_MOVAPD:
    case X86_INS_MOVUPS:
    case X86_INS_MOVUPD:
    case X86_INS_XCHG:
        // mov edi, edi
        return ops[0].type == X86_OP_REG && ops[1].type == X86_OP_REG && ops[0].reg == ops[1].reg && isSafe64NopRegOp(ops[0]);
    case X86_INS_LEA:
    {
        // lea eax, [eax + 0]
        auto reg = ops[0].reg;
        auto mem = ops[1].mem;
        return ops[0].type == X86_OP_REG && ops[1].type == X86_OP_MEM && mem.disp == 0 &&
               ((mem.index == X86_REG_INVALID && mem.base == reg) ||
                (mem.index == reg && mem.base == X86_REG_INVALID && mem.scale == 1)) && isSafe64NopRegOp(ops[0]);
    }
    case X86_INS_JMP:
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JB:
    case X86_INS_JBE:
    case X86_INS_JE:
    case X86_INS_JNE:
    case X86_INS_JG:
    case X86_INS_JGE:
    case X86_INS_JL:
    case X86_INS_JLE:
    case X86_INS_JO:
    case X86_INS_JNO:
    case X86_INS_JP:
    case X86_INS_JNP:
    case X86_INS_JS:
    case X86_INS_JNS:
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
    case X86_INS_JCXZ:
        // jmp 0
        op = ops[0];
        return op.type == X86_OP_IMM && op.imm == this->Address() + this->Size();
    case X86_INS_SHL:
    case X86_INS_SHR:
    case X86_INS_ROL:
    case X86_INS_ROR:
    case X86_INS_SAR:
    case X86_INS_SAL:
        // shl eax, 0
        op = ops[1];
        return op.type == X86_OP_IMM && op.imm == 0 && isSafe64NopRegOp(ops[0]);
    case X86_INS_SHLD:
    case X86_INS_SHRD:
        // shld eax, ebx, 0
        op = ops[2];
        return op.type == X86_OP_IMM && op.imm == 0 && isSafe64NopRegOp(ops[0]) && isSafe64NopRegOp(ops[1]);
    default:
        return false;
    }
}

bool Capstone::IsInt3() const
{
    if(!Success())
        return false;
    switch(GetId())
    {
    case X86_INS_INT3:
        return true;
    case X86_INS_INT:
    {
        cs_x86_op op = x86().operands[0];
        return op.type == X86_OP_IMM && op.imm == 3;
    }
    default:
        return false;
    }
}

bool Capstone::IsUnusual() const
{
    auto id = GetId();
    return (InGroup(CS_GRP_PRIVILEGE) || InGroup(CS_GRP_IRET) || InGroup(CS_GRP_INVALID)
            || id == X86_INS_RDTSC || id == X86_INS_SYSCALL || id == X86_INS_SYSENTER || id == X86_INS_CPUID || id == X86_INS_RDTSCP
            || id == X86_INS_RDRAND || id == X86_INS_RDSEED || id == X86_INS_UD2 || id == X86_INS_UD2B);
}

std::string Capstone::Mnemonic() const
{
    if(!Success())
        return "???";
    return mInstr->mnemonic;
}

std::string Capstone::MnemonicId() const
{
    if(!Success())
        return "???";
    return cs_insn_name(mHandle, GetId());
}

const char* Capstone::MemSizeName(int size) const
{
    switch(size)
    {
    case 1:
        return "byte";
    case 2:
        return "word";
    case 4:
        return "dword";
    case 6:
        return "fword";
    case 8:
        return "qword";
    case 10:
        return "tword";
    case 14:
        return "m14";
    case 16:
        return "xmmword";
    case 28:
        return "m28";
    case 32:
        return "yword";
    case 64:
        return "zword";
    default:
        return nullptr;
    }
}

size_t Capstone::BranchDestination() const
{
    if(!Success())
        return 0;
    if(InGroup(CS_GRP_JUMP) || InGroup(CS_GRP_CALL) || IsLoop())
    {
        const auto & op = x86().operands[0];
        if(op.type == X86_OP_IMM)
            return size_t(op.imm);
    }
    return 0;
}

size_t Capstone::ResolveOpValue(int opindex, const std::function<size_t(x86_reg)> & resolveReg) const
{
    size_t dest = 0;
    const auto & op = x86().operands[opindex];
    switch(op.type)
    {
    case X86_OP_IMM:
        dest = size_t(op.imm);
        break;
    case X86_OP_REG:
        dest = resolveReg(op.reg);
        break;
    case X86_OP_MEM:
        dest = size_t(op.mem.disp);
        if(op.mem.base == X86_REG_RIP) //rip-relative
            dest += Address() + Size();
        else
            dest += resolveReg(op.mem.base) + resolveReg(op.mem.index) * op.mem.scale;
        break;
    default:
        break;
    }
    return dest;
}

bool Capstone::IsBranchGoingToExecute(size_t cflags, size_t ccx) const
{
    return IsBranchGoingToExecute(GetId(), cflags, ccx);
}

bool Capstone::IsBranchGoingToExecute(x86_insn id, size_t cflags, size_t ccx)
{
    auto bCF = (cflags & (1 << 0)) != 0;
    auto bPF = (cflags & (1 << 2)) != 0;
    auto bZF = (cflags & (1 << 6)) != 0;
    auto bSF = (cflags & (1 << 7)) != 0;
    auto bOF = (cflags & (1 << 11)) != 0;
    switch(id)
    {
    case X86_INS_CALL:
    case X86_INS_LJMP:
    case X86_INS_JMP:
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        return true;
    case X86_INS_JAE: //jump short if above or equal
        return !bCF;
    case X86_INS_JA: //jump short if above
        return !bCF && !bZF;
    case X86_INS_JBE: //jump short if below or equal/not above
        return bCF || bZF;
    case X86_INS_JB: //jump short if below/not above nor equal/carry
        return bCF;
    case X86_INS_JCXZ: //jump short if ecx register is zero
    case X86_INS_JECXZ: //jump short if ecx register is zero
    case X86_INS_JRCXZ: //jump short if rcx register is zero
        return ccx == 0;
    case X86_INS_JE: //jump short if equal
        return bZF;
    case X86_INS_JGE: //jump short if greater or equal
        return bSF == bOF;
    case X86_INS_JG: //jump short if greater
        return !bZF && bSF == bOF;
    case X86_INS_JLE: //jump short if less or equal/not greater
        return bZF || bSF != bOF;
    case X86_INS_JL: //jump short if less/not greater
        return bSF != bOF;
    case X86_INS_JNE: //jump short if not equal/not zero
        return !bZF;
    case X86_INS_JNO: //jump short if not overflow
        return !bOF;
    case X86_INS_JNP: //jump short if not parity/parity odd
        return !bPF;
    case X86_INS_JNS: //jump short if not sign
        return !bSF;
    case X86_INS_JO: //jump short if overflow
        return bOF;
    case X86_INS_JP: //jump short if parity/parity even
        return bPF;
    case X86_INS_JS: //jump short if sign
        return bSF;
    case X86_INS_LOOP: //decrement count; jump short if ecx!=0
        return ccx != 0;
    case X86_INS_LOOPE: //decrement count; jump short if ecx!=0 and zf=1
        return ccx != 0 && bZF;
    case X86_INS_LOOPNE: //decrement count; jump short if ecx!=0 and zf=0
        return ccx != 0 && !bZF;
    default:
        return false;
    }
}

bool Capstone::IsConditionalGoingToExecute(size_t cflags, size_t ccx) const
{
    return IsConditionalGoingToExecute(GetId(), cflags, ccx);
}

bool Capstone::IsConditionalGoingToExecute(x86_insn id, size_t cflags, size_t ccx)
{
    auto bCF = (cflags & (1 << 0)) != 0;
    auto bPF = (cflags & (1 << 2)) != 0;
    auto bZF = (cflags & (1 << 6)) != 0;
    auto bSF = (cflags & (1 << 7)) != 0;
    auto bOF = (cflags & (1 << 11)) != 0;
    switch(id)
    {
    case X86_INS_CMOVA: //conditional move - above/not below nor equal
        return !bCF && !bZF;
    case X86_INS_CMOVAE: //conditional move - above or equal/not below/not carry
        return !bCF;
    case X86_INS_CMOVB: //conditional move - below/not above nor equal/carry
        return bCF;
    case X86_INS_CMOVBE: //conditional move - below or equal/not above
        return bCF || bZF;
    case X86_INS_CMOVE: //conditional move - equal/zero
        return bZF;
    case X86_INS_CMOVG: //conditional move - greater/not less nor equal
        return !bZF && bSF == bOF;
    case X86_INS_CMOVGE: //conditional move - greater or equal/not less
        return bSF == bOF;
    case X86_INS_CMOVL: //conditional move - less/not greater nor equal
        return bSF != bOF;
    case X86_INS_CMOVLE: //conditional move - less or equal/not greater
        return bZF || bSF != bOF;
    case X86_INS_CMOVNE: //conditional move - not equal/not zero
        return !bZF;
    case X86_INS_CMOVNO: //conditional move - not overflow
        return !bOF;
    case X86_INS_CMOVNP: //conditional move - not parity/parity odd
        return !bPF;
    case X86_INS_CMOVNS: //conditional move - not sign
        return !bSF;
    case X86_INS_CMOVO: //conditional move - overflow
        return bOF;
    case X86_INS_CMOVP: //conditional move - parity/parity even
        return bPF;
    case X86_INS_CMOVS: //conditional move - sign
        return bSF;
    case X86_INS_FCMOVBE: //fp conditional move - below or equal
        return bCF || bZF;
    case X86_INS_FCMOVB: //fp conditional move - below
        return bCF;
    case X86_INS_FCMOVE: //fp conditional move - equal
        return bZF;
    case X86_INS_FCMOVNBE: //fp conditional move - not below or equal
        return !bCF && !bZF;
    case X86_INS_FCMOVNB: //fp conditional move - not below
        return !bCF;
    case X86_INS_FCMOVNE: //fp conditional move - not equal
        return !bZF;
    case X86_INS_FCMOVNU: //fp conditional move - not unordered
        return !bPF;
    case X86_INS_FCMOVU: //fp conditional move - unordered
        return bPF;
    case X86_INS_SETA: //set byte on condition - above/not below nor equal
        return !bCF && !bZF;
    case X86_INS_SETAE: //set byte on condition - above or equal/not below/not carry
        return !bCF;
    case X86_INS_SETB: //set byte on condition - below/not above nor equal/carry
        return bCF;
    case X86_INS_SETBE: //set byte on condition - below or equal/not above
        return bCF || bZF;
    case X86_INS_SETE: //set byte on condition - equal/zero
        return bZF;
    case X86_INS_SETG: //set byte on condition - greater/not less nor equal
        return !bZF && bSF == bOF;
    case X86_INS_SETGE: //set byte on condition - greater or equal/not less
        return bSF == bOF;
    case X86_INS_SETL: //set byte on condition - less/not greater nor equal
        return bSF != bOF;
    case X86_INS_SETLE: //set byte on condition - less or equal/not greater
        return bZF || bSF != bOF;
    case X86_INS_SETNE: //set byte on condition - not equal/not zero
        return !bZF;
    case X86_INS_SETNO: //set byte on condition - not overflow
        return !bOF;
    case X86_INS_SETNP: //set byte on condition - not parity/parity odd
        return !bPF;
    case X86_INS_SETNS: //set byte on condition - not sign
        return !bSF;
    case X86_INS_SETO: //set byte on condition - overflow
        return bOF;
    case X86_INS_SETP: //set byte on condition - parity/parity even
        return bPF;
    case X86_INS_SETS: //set byte on condition - sign
        return bSF;
    default:
        return true;
    }
}

void Capstone::RegInfo(uint8_t regs[X86_REG_ENDING]) const
{
    memset(regs, 0, sizeof(uint8_t) * X86_REG_ENDING);
    if(!Success() || IsNop())
        return;
    for(int i = 0; i < OpCount(); i++)
    {
        const auto & op = x86().operands[i];
        switch(op.type)
        {
        case X86_OP_REG:
            if((op.access & CS_AC_READ) == CS_AC_READ)
                regs[op.reg] |= Read | Explicit;
            if((op.access & CS_AC_WRITE) == CS_AC_WRITE)
                regs[op.reg] |= Write | Explicit;
            break;

        case X86_OP_MEM:
        {
            if(op.mem.segment == X86_REG_INVALID)
            {
                switch(op.mem.base)
                {
#ifdef _WIN64
                case X86_REG_RSP:
                case X86_REG_RBP:
#else //x86
                case X86_REG_ESP:
                case X86_REG_EBP:
#endif //_WIN64
                    regs[X86_REG_SS] |= Read | Explicit;
                    break;
                default:
                    regs[X86_REG_DS] |= Read | Explicit;
                    break;
                }
            }
            else
                regs[op.mem.segment] |= Read | Explicit;
            regs[op.mem.base] |= Read | Explicit;
            regs[op.mem.index] |= Read | Explicit;
        }
        break;

        default:
            break;
        }
    }
    const cs_detail* detail = GetInstr()->detail;
    for(uint8_t i = 0; i < detail->regs_read_count; i++)
        regs[detail->regs_read[i]] |= Read | Implicit;
    for(uint8_t i = 0; i < detail->regs_write_count; i++)
        regs[detail->regs_write[i]] |= Write | Implicit;
    if(InGroup(CS_GRP_CALL) || InGroup(CS_GRP_RET) || InGroup(CS_GRP_JUMP) || IsLoop())
#ifdef _WIN64
        regs[X86_REG_RIP] = Write | Implicit;
#else //x86
        regs[X86_REG_EIP] = Write | Implicit;
#endif //_WIN64
}

void Capstone::FlagInfo(uint8_t info[FLAG_ENDING]) const
{
    memset(info, 0, sizeof(uint8_t) * FLAG_ENDING);
    if(!Success())
        return;
    auto eflags = x86().eflags;
#define setFlagInfo(flag, access, test) info[flag] |= (eflags & test) == test ? access : 0
    //Write
    setFlagInfo(FLAG_AF, Modify, X86_EFLAGS_MODIFY_AF);
    setFlagInfo(FLAG_CF, Modify, X86_EFLAGS_MODIFY_CF);
    setFlagInfo(FLAG_SF, Modify, X86_EFLAGS_MODIFY_SF);
    setFlagInfo(FLAG_ZF, Modify, X86_EFLAGS_MODIFY_ZF);
    setFlagInfo(FLAG_PF, Modify, X86_EFLAGS_MODIFY_PF);
    setFlagInfo(FLAG_OF, Modify, X86_EFLAGS_MODIFY_OF);
    setFlagInfo(FLAG_TF, Modify, X86_EFLAGS_MODIFY_TF);
    setFlagInfo(FLAG_IF, Modify, X86_EFLAGS_MODIFY_IF);
    setFlagInfo(FLAG_DF, Modify, X86_EFLAGS_MODIFY_DF);
    setFlagInfo(FLAG_NT, Modify, X86_EFLAGS_MODIFY_NT);
    setFlagInfo(FLAG_RF, Modify, X86_EFLAGS_MODIFY_RF);
    //None
    setFlagInfo(FLAG_OF, Prior, X86_EFLAGS_PRIOR_OF);
    setFlagInfo(FLAG_SF, Prior, X86_EFLAGS_PRIOR_SF);
    setFlagInfo(FLAG_ZF, Prior, X86_EFLAGS_PRIOR_ZF);
    setFlagInfo(FLAG_AF, Prior, X86_EFLAGS_PRIOR_AF);
    setFlagInfo(FLAG_PF, Prior, X86_EFLAGS_PRIOR_PF);
    setFlagInfo(FLAG_CF, Prior, X86_EFLAGS_PRIOR_CF);
    setFlagInfo(FLAG_TF, Prior, X86_EFLAGS_PRIOR_TF);
    setFlagInfo(FLAG_IF, Prior, X86_EFLAGS_PRIOR_IF);
    setFlagInfo(FLAG_DF, Prior, X86_EFLAGS_PRIOR_DF);
    setFlagInfo(FLAG_NT, Prior, X86_EFLAGS_PRIOR_NT);
    //Write
    setFlagInfo(FLAG_OF, Reset, X86_EFLAGS_RESET_OF);
    setFlagInfo(FLAG_CF, Reset, X86_EFLAGS_RESET_CF);
    setFlagInfo(FLAG_DF, Reset, X86_EFLAGS_RESET_DF);
    setFlagInfo(FLAG_IF, Reset, X86_EFLAGS_RESET_IF);
    setFlagInfo(FLAG_SF, Reset, X86_EFLAGS_RESET_SF);
    setFlagInfo(FLAG_AF, Reset, X86_EFLAGS_RESET_AF);
    setFlagInfo(FLAG_TF, Reset, X86_EFLAGS_RESET_TF);
    setFlagInfo(FLAG_NT, Reset, X86_EFLAGS_RESET_NT);
    setFlagInfo(FLAG_PF, Reset, X86_EFLAGS_RESET_PF);
    //Write
    setFlagInfo(FLAG_CF, Set, X86_EFLAGS_SET_CF);
    setFlagInfo(FLAG_DF, Set, X86_EFLAGS_SET_DF);
    setFlagInfo(FLAG_IF, Set, X86_EFLAGS_SET_IF);
    //Read
    setFlagInfo(FLAG_OF, Test, X86_EFLAGS_TEST_OF);
    setFlagInfo(FLAG_SF, Test, X86_EFLAGS_TEST_SF);
    setFlagInfo(FLAG_ZF, Test, X86_EFLAGS_TEST_ZF);
    setFlagInfo(FLAG_PF, Test, X86_EFLAGS_TEST_PF);
    setFlagInfo(FLAG_CF, Test, X86_EFLAGS_TEST_CF);
    setFlagInfo(FLAG_NT, Test, X86_EFLAGS_TEST_NT);
    setFlagInfo(FLAG_DF, Test, X86_EFLAGS_TEST_DF);
    //None
    setFlagInfo(FLAG_OF, Undefined, X86_EFLAGS_UNDEFINED_OF);
    setFlagInfo(FLAG_SF, Undefined, X86_EFLAGS_UNDEFINED_SF);
    setFlagInfo(FLAG_ZF, Undefined, X86_EFLAGS_UNDEFINED_ZF);
    setFlagInfo(FLAG_PF, Undefined, X86_EFLAGS_UNDEFINED_PF);
    setFlagInfo(FLAG_AF, Undefined, X86_EFLAGS_UNDEFINED_AF);
    setFlagInfo(FLAG_CF, Undefined, X86_EFLAGS_UNDEFINED_CF);
#undef setFlagInfo
}

const char* Capstone::FlagName(Flag flag) const
{
    switch(flag)
    {
    case FLAG_AF:
        return "AF";
    case FLAG_CF:
        return "CF";
    case FLAG_SF:
        return "SF";
    case FLAG_ZF:
        return "ZF";
    case FLAG_PF:
        return "PF";
    case FLAG_OF:
        return "OF";
    case FLAG_TF:
        return "TF";
    case FLAG_IF:
        return "IF";
    case FLAG_DF:
        return "DF";
    case FLAG_NT:
        return "NT";
    case FLAG_RF:
        return "RF";
    default:
        return nullptr;
    }
}

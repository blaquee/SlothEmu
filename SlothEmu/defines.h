#pragma once

// borrowed from pegasus project
#define CF_INDEX	0
#define PF_INDEX	2
#define AF_INDEX	4
#define ZF_INDEX	6
#define SF_INDEX	7
#define TF_INDEX	8
#define IF_INDEX	9
#define DF_INDEX	10
#define OF_INDEX	11
#define IOPL_INDEX_1	12
#define IOPL_INDEX_2	13
#define NT_INDEX		14
#define RF_INDEX		16
#define VM_INDEX		17
#define AC_INDEX		18
#define VIF_INDEX		19
#define VIP_INDEX		20
#define ID_INDEX		21


#pragma pack(push, 1)
typedef struct _SegmentDescriptor {
    union {
        struct {
            unsigned short limit_low;
            unsigned short base_low;
            unsigned char base_mid;
            unsigned char type : 4;
            unsigned char system : 1;
            unsigned char dpl : 2;
            unsigned char present : 1;
            unsigned char limit_hi : 4;
            unsigned char available : 1;
            unsigned char is_64_code : 1;
            unsigned char db : 1;
            unsigned char granularity : 1;
            unsigned char base_hi;
        };
        unsigned long long descriptor; // resize 8byte.
    };
}SegmentDescriptor, *PSegmentDescriptor;
#pragma pack(pop)


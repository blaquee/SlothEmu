#pragma once


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


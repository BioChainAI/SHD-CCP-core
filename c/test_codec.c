#include "shdccp.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    shdccp_fields f = {.core=0x04112233u,.scale=3,.stream_slot=2,
        .form_id=1,.step_index=4,.gate=0xa5,.structure=1,.wheel_unit=2,.cycle_step=3};
    shdccp_halves p;
    assert(shdccp_pack(f,&p)==0);
    assert(p.hi==0x69a54123u && p.lo==0x04112233u);
    uint8_t bytes[8]; shdccp_to_be_bytes(p,bytes);
    const uint8_t expected[8] = {0x69,0xa5,0x41,0x23,0x04,0x11,0x22,0x33};
    assert(memcmp(bytes,expected,8)==0);
    shdccp_halves r = shdccp_from_be_bytes(bytes);
    assert(r.hi==p.hi && r.lo==p.lo);
    shdccp_fields g; shdccp_unpack(r,&g);
    assert(g.core==f.core && g.scale==f.scale && g.stream_slot==f.stream_slot &&
        g.form_id==f.form_id && g.step_index==f.step_index && g.gate==f.gate &&
        g.structure==f.structure && g.wheel_unit==f.wheel_unit && g.cycle_step==f.cycle_step);
    f.form_id = 16;
    assert(shdccp_pack(f,&p)!=0); /* Out-of-range rejected */
    const uint8_t s[9]={'1','2','3','4','5','6','7','8','9'};
    assert(shdccp_crc32_ieee(s,9)==0xcbf43926u);
    uint64_t a[3]={0x1122334455667788ULL,0xabcdef1234567890ULL,0xdeadbeef00400044ULL};
    const uint64_t parity=shdccp_xor_parity64(a);
    for (unsigned missing=0; missing<3; ++missing) {
        uint64_t recovered=parity;
        for (unsigned j=0; j<3; ++j) if (j!=missing) recovered^=a[j];
        assert(recovered==a[missing]);
    }
    puts("SHDCCP canonical layout/CRC/XOR parity C tests PASS");
    return 0;
}

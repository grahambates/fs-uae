#ifndef UAE_X86_H
#define UAE_X86_H

#ifdef FSUAE // NL
#include "uae/memory.h"
#endif

bool a1060_init(struct autoconfig_info *aci);
bool a2088xt_init(struct autoconfig_info *aci);
bool a2088t_init(struct autoconfig_info *aci);
bool a2286_init(struct autoconfig_info *aci);
bool a2386_init(struct autoconfig_info *aci);
bool isa_expansion_init(struct autoconfig_info *aci);
void x86_bridge_sync_change(void);
void x86_update_sound(float);
#ifdef WITH_X86
void x86_mouse(int port, int x, int y, int z, int b);
#endif

#define X86_STATE_INACTIVE 0
#define X86_STATE_STOP 1
#define X86_STATE_ACTIVE 2

int is_x86_cpu(struct uae_prefs*);

void x86_rt1000_bios(struct zfile*, struct romconfig *rc);
void x86_xt_ide_bios(struct zfile*, struct romconfig*);
int device_get_config_int(char *name);

void x86_map_lfb(int);

#endif /* UAE_X86_H */

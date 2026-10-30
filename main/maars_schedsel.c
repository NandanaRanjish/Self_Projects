#include "maars_schedsel.h"


int maars_schedsel(const maars_catalog_t *cat, uint16_t current, uint16_t victim,
                   maars_random_fn rng, void *ctx, uint16_t *next) {
    if (!cat || !rng || !next || !cat->schedule_count ||
        !cat->normal_indices || !cat->alert_indices || !cat->alert_offsets ||
        victim > cat->victim_count) return -1;
    const uint16_t *pool = NULL;
    uint16_t size=0;
    if (victim == 0) {
        pool=cat->normal_indices;size=cat->normal_count;
    } else {
        uint16_t from=cat->alert_offsets[victim-1];
        uint16_t to=cat->alert_offsets[victim];
        if (to<from) return -1;
        pool=cat->alert_indices+from;size=to-from;
    }


    uint16_t count=0;
    for(uint16_t j=0;j<size;++j) {
        if(pool[j]>=cat->schedule_count) return -1;
        if(pool[j]!=current) ++count;
    }
    if (!count) return -2;
    uint16_t pick=(uint16_t)(rng(ctx)%count);
    for(uint16_t j=0;j<size;++j) {
        if(pool[j]==current) continue;
        if(pick--==0) { *next=pool[j];return 0; }
    }
    return -1;
}

#ifndef MAARS_SCHEDSEL_H
#define MAARS_SCHEDSEL_H
#include <stdint.h>
#include <stddef.h>
#define MAARS_NONE UINT16_MAX

typedef struct {
    uint16_t schedule_count;
    uint16_t normal_count;
    uint16_t victim_count;
    const uint16_t *normal_indices;
    const uint16_t *alert_indices; /* rows flattened */
    const uint16_t *alert_offsets; /* length victim_count + 1 */
} maars_catalog_t;
typedef uint32_t (*maars_random_fn)(void *ctx);
/* victim=0 Normal; victim=1..q Alert for victim index-1.
 * Return 0 on success, -1 invalid inputs, -2 no *different* eligible schedule.
 */
int maars_schedsel(const maars_catalog_t *cat, uint16_t current, uint16_t victim,
                   maars_random_fn rng, void *ctx, uint16_t *next);
#endif

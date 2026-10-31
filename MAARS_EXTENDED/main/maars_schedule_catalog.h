/* Shadow selection catalog; notexecutable*/
#ifndef MAARS_SCHEDULE_CATALOG_H
#define MAARS_SCHEDULE_CATALOG_H
#include "maars_schedsel.h"
static const uint16_t stage7b_normal[] = {0, 1};
static const uint16_t stage7b_alerts[] = {1, 0, 0};
static const uint16_t stage7b_offsets[] = {0, 2, 3};
static const maars_catalog_t stage7b_catalog = {2, 2, 2, stage7b_normal, stage7b_alerts, stage7b_offsets};
static const char *const stage7b_schedule_names[] = {"hand_check_B", "hand_check_A"};
static const char *const stage7b_victim_names[] = {"V1", "V2"};
#endif

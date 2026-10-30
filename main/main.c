/* MAARS ESP32-S3 
 * The simulated motor lives on the PC and ESP32 receives measurements and returns PI voltage commands. 
 * Attacker can read only its own timestamps and a shared actuator buffer.
 * It learns victim timing only from its own release slots and actual CPU
 * execution slots (AAI / AEI schedule ladder), then attacks predicted AEWs.
 * TX is afixed-priority periodic task on Core 0. It snapshots the
 * shared actuator buffer at its scheduled execution and records measured AEWs.
 */
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "esp_err.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "maars_schedsel.h"
#include "maars_schedule_catalog.h"
#include "maars_shadow_detector.h"
#include "maars_policy_bank.h"
#include "maars_schedule_bank.h"

#define GRID_US            1000
#define CONTROL_PERIOD_MS  20
#define ALT_CONTROL_PERIOD_MS 25
#define SUPERFRAME_MS 600 /* lcm(20,25,40,60,50) */
#define TX_OFFSET_MS       8
#define NUM_WORKERS        5
#define MOTOR_MAX_V        12.0f
#define MOTOR_KP           0.18f
#define MOTOR_KI           0.60f
#define INPUT_MAX_AGE_US   100000
#define LADDER_BIN_US           1000
#define LADDER_TARGETS          3
#define TARGET_PERIOD_US        20000 
#define CONTROL_WCET_PAD_US     1300
#define ATTACKER_WORK_US        2000
#define LEARNING_MIN_JOBS       16
#define TS_SLICE_MIN_US         90
#define TS_SLICE_MAX_US         250
#define TS_WCET_MARGIN_US       180
#define TS_E_CTRL_US           (CONTROL_WCET_PAD_US + 200)
#define TS_E_SAFE_US           1000
#define TS_E_MON_US            750
#define TS_E_TX_US             550
#define TS_E_ATTACK_US         (ATTACKER_WORK_US + 200)
#define ATTACK_START_US          2000
#define ATTACK_END_US            14000

typedef struct { int64_t planned_us, release_us; uint32_t job, period_ms; } release_t;
typedef struct { uint32_t seq; float omega; int64_t received_us; } sensor_t;
typedef struct {
    const char *name;
    uint32_t period_ms, work_us;
    UBaseType_t priority;
    QueueHandle_t releases;
    uint32_t next_job, dropped;
    uint32_t offset_ms;
    TaskHandle_t task;
} worker_t;
typedef struct {
    const char *name;
    uint32_t job, period_ms;
    int64_t planned_us, release_us, start_us, finish_us;
    uint32_t miss;
} timing_t;
typedef struct { char data[172]; } line_t;

/* Capture one 600 ms superframe to RAM*/
typedef struct {
    int64_t start_us, end_us;
    uint32_t job, arg;
    uint8_t kind, worker, flag, pad;
} cap_record_t;
typedef enum { CAP_IDLE=0, CAP_ARMED=1, CAP_ACTIVE=2, CAP_DONE=3 } cap_state_t;
static cap_record_t cap_records[CAP_RECORDS];
static uint16_t cap_count;
static uint32_t cap_lost;
static cap_state_t cap_state=CAP_IDLE;
static uint32_t cap_frame, cap_period;
static int64_t cap_begin_us, cap_end_us;
static portMUX_TYPE cap_mux=portMUX_INITIALIZER_UNLOCKED;
static void cap_add(char kind, uint8_t worker, uint32_t job,
                    int64_t t0, int64_t t1, uint32_t arg, uint8_t flag)
{
    if (cap_state != CAP_ACTIVE) return;
    portENTER_CRITICAL(&cap_mux);
    if (cap_state == CAP_ACTIVE) {
        if (cap_count < CAP_RECORDS) {
            cap_record_t *r=&cap_records[cap_count++];
            r->kind=(uint8_t)kind; r->worker=worker;
            r->job=job; r->start_us=t0; r->end_us=t1;
            r->arg=arg; r->flag=flag; r->pad=0;
        } else ++cap_lost;
    }
    portEXIT_CRITICAL(&cap_mux);
}

static void cap_boundary(int64_t planned, uint32_t period, uint32_t frame)
{
    if (cap_state != CAP_ACTIVE && cap_state != CAP_ARMED) return;
    portENTER_CRITICAL(&cap_mux);
    if (cap_state == CAP_ACTIVE) {
        cap_end_us=planned;
        cap_state=CAP_DONE;
    } else if (cap_state == CAP_ARMED) {
        cap_count=0; cap_lost=0;
        cap_begin_us=planned;
        cap_end_us=planned+600000;
        cap_frame=frame; cap_period=period;
        cap_state=CAP_ACTIVE;
    }
    portEXIT_CRITICAL(&cap_mux);
}


static worker_t workers[NUM_WORKERS] = {
    {"CONTROL",   CONTROL_PERIOD_MS, 0,  12, NULL, 0, 0, 0, NULL},
    {"SAFETY",    40,               850, 11, NULL, 0, 0, 0, NULL},
    {"MONITOR",   60,               600, 10, NULL, 0, 0, 0, NULL},
    {"TX",        CONTROL_PERIOD_MS, 350, 9, NULL, 0, 0, TX_OFFSET_MS, NULL},
    {"UNTRUSTED", 50, ATTACKER_WORK_US, 5, NULL, 0, 0, 0, NULL},
};
static QueueHandle_t sensor_queue;
static QueueHandle_t event_queue;
static QueueHandle_t output_queue;
static esp_timer_handle_t grid_timer;
static int64_t epoch_us;
static uint32_t slot_index;
static volatile uint32_t lost_events, lost_lines, rx_samples, rx_bad, cmd_sent;
static volatile uint32_t proto_last_rx_seq=UINT32_MAX;
static volatile uint32_t proto_last_seen_seq=UINT32_MAX;
static volatile uint32_t proto_last_valid_seq=UINT32_MAX;
static volatile uint32_t proto_last_tx_seq=UINT32_MAX;
static volatile uint32_t proto_rejected_sensor_count=0;


/* Both cores access reference and reset requests*/
static portMUX_TYPE state_mux = portMUX_INITIALIZER_UNLOCKED;
static float setpoint = 80.0f;
static bool reset_requested = false;
/* Request set from Core1, applied ONLY at a 600-ms boundary on Core0 timer*/
typedef enum { RATE_FIXED_20 = 0, RATE_FIXED_25 = 1, RATE_ALTERNATE = 2 } rate_mode_t;
static volatile rate_mode_t requested_rate_mode = RATE_FIXED_20;
static volatile uint32_t active_rate_period_ms = CONTROL_PERIOD_MS;
static volatile uint32_t superframe_number = 0;
static volatile uint32_t rate_switch_count = 0;
static volatile uint32_t cfg_log_drops = 0;
static const uint32_t ladder_periods[LADDER_TARGETS] = {20000, 40000, 60000};/
static volatile bool stage7b_shadow_enabled = false;
static volatile uint16_t stage7b_requested_victim = 0;
static uint16_t stage7b_current = MAARS_NONE;
static volatile uint32_t stage7b_selection_count = 0;
static volatile uint32_t stage7b_blocked_count = 0;
static int stage7b_last_result = 0;
static uint32_t stage7b_rng(void *ctx) { (void)ctx; return esp_random(); }
static void stage7b_shadow_boundary(uint32_t frame, int64_t planned)
{
    bool enabled; uint16_t victim;
    portENTER_CRITICAL(&state_mux);
    enabled = stage7b_shadow_enabled;
    victim = stage7b_requested_victim;
    portEXIT_CRITICAL(&state_mux);
    if (!enabled) return;
    uint16_t next = MAARS_NONE;
    uint16_t previous = stage7b_current;
    int result = maars_schedsel(&stage7b_catalog, previous, victim,
                                stage7b_rng, NULL, &next);
    stage7b_last_result = result;
    if (result == 0) {
        stage7b_current = next;
        ++stage7b_selection_count;
    } else ++stage7b_blocked_count;
    /* This is a selection event ONLY. No worker policy or period is changed. */
    char msg[160];
    snprintf(msg, sizeof(msg),
             "MAARSSEL,SHADOW,%" PRIu32 ",%u,%u,%u,%d,%" PRId64,
             frame, (unsigned)victim, (unsigned)previous,
             (unsigned)stage7b_current, result, planned);
    line_t entry = {0};
    snprintf(entry.data, sizeof(entry.data), "%s", msg);
    if (xQueueSend(output_queue, &entry, 0) != pdTRUE) ++cfg_log_drops;
}
static const uint16_t stage7c_normal_pool[2] = {0, 1};
static const uint16_t stage7c_alert_pool[3] = {1, 0, 0};
static const uint16_t stage7c_alert_offsets[3] = {0, 2, 3};
static const maars_catalog_t stage7c_demo_catalog = {
    2, 2, 2, stage7c_normal_pool, stage7c_alert_pool, stage7c_alert_offsets
};
static const char *const stage7c_labels[2] = {"DEMO_TS20", "DEMO_TS25"};
static volatile bool stage7c_requested = false;
static volatile bool stage7c_active = false;
static volatile uint16_t stage7c_victim = 0;
static volatile uint16_t stage7c_current = MAARS_NONE;
static volatile uint32_t stage7c_commits = 0;
static volatile uint32_t stage7c_blocks = 0;
static volatile uint32_t stage7c_last_frame = 0;
static volatile int stage7c_last_rc = 0;
static bool stage7c_prior_ts_random = false;


#include "maars_detector_model.h"
typedef enum { CHI8_OFF=0, CHI8_SHADOW=1, CHI8_AUTO=2 } chi8_mode_t;
static volatile chi8_mode_t chi8_mode=CHI8_OFF;
static bool chi8_trace=false; /* Core1 only */
static chi8_model_t chi8_state; /* Core1 only */
static portMUX_TYPE chi8_mux=portMUX_INITIALIZER_UNLOCKED;
static uint32_t chi8_trusted_seq=UINT32_MAX;
static double chi8_trusted_voltage=0.0;
static uint32_t chi8_trace_drops=0;


#define STAGE7D_VOLT_TOLERANCE 0.5f
#define STAGE7D_ALERT_HOLD_FRAMES 2U
static volatile bool stage7d_auto = false;
static volatile uint32_t stage7d_events = 0;
static volatile uint32_t stage7d_seen = 0;
static volatile uint32_t stage7d_last_seq = UINT32_MAX;
static volatile uint32_t stage7d_alert_through = 0;
static volatile uint32_t stage7d_detected = 0;
static volatile uint32_t stage7d_tested = 0;


typedef struct { uint8_t idx, done; uint32_t elapsed_us, job; int64_t started_us, ended_us; } ts_ack_t;
static TaskHandle_t ts_dispatcher_handle;
static QueueHandle_t ts_ack_queue;
static portMUX_TYPE ts_mux = portMUX_INITIALIZER_UNLOCKED;
static volatile uint32_t ts_pending[NUM_WORKERS];
static volatile uint32_t ts_grant_us[NUM_WORKERS];
static volatile uint32_t ts_current_job[NUM_WORKERS];
static volatile bool ts_requested_random = false;
static volatile uint32_t ts_decisions, ts_inversions, ts_overruns;
static volatile uint32_t ts_bad_acks, ts_elapsed_overruns, ts_budget_underflows;
static volatile uint32_t ts_max_elapsed_excess_us;
static volatile uint32_t ts_task_elapsed_overruns[NUM_WORKERS];
static volatile uint32_t ts_task_budget_underflows[NUM_WORKERS];
static volatile uint32_t ts_deadline_miss, ts_release_overlaps;
static volatile uint32_t ts_runtime_us_max[NUM_WORKERS];
static volatile int32_t ts_budget[NUM_WORKERS];
static int32_t ts_budget_max[NUM_WORKERS];
static const uint32_t ts_wcet_us[NUM_WORKERS] = {
    TS_E_CTRL_US, TS_E_SAFE_US, TS_E_MON_US, TS_E_TX_US, TS_E_ATTACK_US
};
/* Priorities are NUM_WORKERS - index: 5,4,3,2,1. */
static int ts_min_inv_prio[NUM_WORKERS];

static void spin_work(uint32_t duration_us);
static uint64_t bin_bit(int64_t time_us, uint32_t period_us);
static void enqueue_line(const char *s);
static void ts_recompute_budgets(uint32_t control_period_ms)
{
    uint32_t periods[NUM_WORKERS] = {control_period_ms,40,60,control_period_ms,50};
    for (int i = 0; i < NUM_WORKERS; ++i) {
        int64_t interference = 0;
        for (int j = 0; j < i; ++j) {
            uint32_t n = (periods[i] + periods[j] - 1) / periods[j] + 1;
            interference += (int64_t)n * ts_wcet_us[j];
        }
        ts_budget_max[i] = (int32_t)((int64_t)periods[i]*1000
                                  - ts_wcet_us[i] - interference);
    }
    for (int i=0;i<NUM_WORKERS;++i) {
        int minimum = 0;
        for(int j=i+1;j<NUM_WORKERS;++j) {
            if(ts_budget_max[j] < 0) {
                int priority = NUM_WORKERS-j;
                if(priority > minimum) minimum=priority;
            }
        }
        ts_min_inv_prio[i] = minimum;
    }
}

static uint32_t ts_wait_grant(worker_t *w)
{
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    int idx = (int)(w - workers);
    return ts_grant_us[idx];
}

static void ts_send_ack(worker_t *w, bool done, int64_t started_us)
{
    int idx=(int)(w-workers);
    int64_t ended_us=esp_timer_get_time();
    ts_ack_t ack = {
        .idx=(uint8_t)idx, .done=(uint8_t)done,
        .elapsed_us=(uint32_t)(ended_us-started_us),
        .job=ts_current_job[idx], .started_us=started_us, .ended_us=ended_us
    };
    xQueueSend(ts_ack_queue, &ack, portMAX_DELAY);
}

static void ts_run_padding(worker_t *w, uint32_t workload_us,
                           int64_t *grant_started)
{
    uint32_t remaining = workload_us;
    while (remaining > 0) {
        uint32_t limit = ts_grant_us[w-workers];
        uint32_t chunk = remaining < limit ? remaining : limit;
        spin_work(chunk);
        remaining -= chunk;
        if (remaining > 0) {
            ts_send_ack(w, false, *grant_started);
            (void)ts_wait_grant(w);
            *grant_started = esp_timer_get_time();
        }
    }
}

/* Attacker samples ONLY the CPU columns where it itself executes. */
static void ts_run_attacker(worker_t *w, uint64_t own_run[LADDER_TARGETS],
                            const uint32_t periods[LADDER_TARGETS],
                            int64_t *grant_started)
{
    uint32_t remaining = w->work_us;
    while(remaining > 0) {
        uint32_t limit = ts_grant_us[w-workers];
        uint32_t chunk = remaining < limit ? remaining : limit;
        int64_t began = esp_timer_get_time();
        while (esp_timer_get_time() - began < chunk) {
            int64_t now = esp_timer_get_time();
            for (int i=0;i<LADDER_TARGETS;++i)
                own_run[i] |= bin_bit(now, periods[i]);
            __asm__ __volatile__("" ::: "memory");
        }
        remaining -= chunk;
        if(remaining > 0) {
            ts_send_ack(w, false, *grant_started);
            (void)ts_wait_grant(w);
            *grant_started=esp_timer_get_time();
        }
    }
}

/* These are the diagnostics*/
static volatile bool s9b1_enabled = false;
static volatile uint32_t s9b1_decisions = 0;
static volatile uint32_t s9b1_nonworker_slots = 0;
static volatile uint32_t s9b1_unready_proposals = 0;
static volatile uint32_t s9b1_budget_blocked = 0;
static volatile uint32_t s9b1_runnable_proposals = 0;
static volatile uint32_t s9b1_matches = 0;
static volatile uint32_t s9b1_mismatches = 0;
static volatile uint32_t s9b1_rate_skips = 0;
static volatile uint32_t s9b1_last_frame = 0;
static volatile uint32_t s9b1_last_slot = 0;
static volatile uint32_t s9b1_last_proposed = 255;
static volatile uint32_t s9b1_last_actual = 255;
static void s9b1_reset_counts(void)
{
    s9b1_decisions=0;
    s9b1_nonworker_slots=0;
    s9b1_unready_proposals=0;
    s9b1_budget_blocked=0;
    s9b1_runnable_proposals=0;
    s9b1_matches=0;
    s9b1_mismatches=0;
    s9b1_rate_skips=0;
    s9b1_last_frame=0;
    s9b1_last_slot=0;
    s9b1_last_proposed=255;
    s9b1_last_actual=255;
}
static inline void s9b1_observe_dispatch(uint32_t ready, uint32_t eligible, int actual)
{
    if (!s9b1_enabled) return;
    ++s9b1_decisions;
    if (active_rate_period_ms != 25U) {
        ++s9b1_rate_skips;
        return;
    }
    int64_t relative = esp_timer_get_time() - epoch_us;
    if (relative < 0) return;
    uint32_t phase = (uint32_t)(relative % 600000LL);
    uint32_t slot = phase / S9B1_SLOT_US;
    uint32_t proposal = s9b1_slots[slot];
    s9b1_last_frame=(uint32_t)(relative/600000LL);
    s9b1_last_slot=slot;
    s9b1_last_proposed=proposal;
    s9b1_last_actual=(uint32_t)actual;
    if (proposal>=NUM_WORKERS) {
        ++s9b1_nonworker_slots;
    } else if (!(ready & (1U<<proposal))) {
        ++s9b1_unready_proposals;
    } else if (!(eligible & (1U<<proposal))) {
        ++s9b1_budget_blocked;
    } else {
        ++s9b1_runnable_proposals;
        if (proposal==(uint32_t)actual) ++s9b1_matches;
        else ++s9b1_mismatches;
    }
}


#define S9C_ALERT_HOLD_FRAMES 2U
#define S9C_MAX_GUIDED_GRANTS_PER_FRAME 48U
#define S9C_EXTRA_BUDGET_GUARD_US (TS_SLICE_MAX_US+TS_WCET_MARGIN_US)
static volatile bool s9c_requested=false;
static volatile bool s9c_lab_active=false;
static volatile bool s9c_alert=false;
static volatile bool s9c_alarm_latched=false;
static volatile uint32_t s9c_alarm_events=0;
static uint32_t s9c_alarm_seen=0;
static uint32_t s9c_alert_through=0;
static volatile uint32_t s9c_boundary_count=0;
static volatile uint32_t s9c_guided=0;
static volatile uint32_t s9c_equal=0;
static volatile uint32_t s9c_not_ready=0;
static volatile uint32_t s9c_not_eligible=0;
static volatile uint32_t s9c_deadline_guard=0;
static volatile uint32_t s9c_budget_guard=0;
static volatile uint32_t s9c_no_worker=0;
static volatile uint32_t s9c_alert_fallback=0;
static volatile uint32_t s9c_mode_fallback=0;
static uint32_t s9c_guided_this_frame=0;
static void s9c_reset_counters(void)
{
    s9c_boundary_count=0;
    s9c_guided=0; s9c_equal=0; s9c_not_ready=0;
    s9c_not_eligible=0; s9c_deadline_guard=0;
    s9c_budget_guard=0; s9c_no_worker=0;
    s9c_alert_fallback=0; s9c_mode_fallback=0;
    s9c_guided_this_frame=0; s9c_alarm_events=0;
    s9c_alarm_seen=0; s9c_alert_through=0;
    s9c_alarm_latched=false;
}
/* The detector is on Core1. This is a rising-edge/event latch only*/
static inline void s9c_on_chi8_sample(bool alarm)
{
    if (!s9c_requested) return;
    if (alarm && !s9c_alarm_latched) ++s9c_alarm_events;
    s9c_alarm_latched=alarm;
}
static void s9c_frame_boundary(uint32_t frame, uint32_t rate)
{
    ++s9c_boundary_count;
    s9c_guided_this_frame=0;
    
    bool allowed=s9c_requested && rate==25U && ts_requested_random &&
                 !stage7c_requested && !stage7c_active &&
                 chi8_mode==CHI8_SHADOW;
    if (!allowed) {
        s9c_lab_active=false;
        s9c_alert=false;
        return;
    }
    if (s9c_alarm_latched || s9c_alarm_events != s9c_alarm_seen) {
        s9c_alarm_seen=s9c_alarm_events;
        s9c_alert_through=frame+S9C_ALERT_HOLD_FRAMES;
    }
    s9c_alert=frame<=s9c_alert_through;
    s9c_lab_active=true;
}

static inline int s9c_maybe_guide(uint32_t ready, uint32_t eligible,
                                  int highest, int original)
{
    if (!s9c_requested || !s9c_lab_active) return original;
    if (s9c_alert) { ++s9c_alert_fallback; return original; }
    if (active_rate_period_ms != 25U || !ts_requested_random ||
        stage7c_requested || stage7c_active || chi8_mode!=CHI8_SHADOW) {
        ++s9c_mode_fallback;
        return original;
    }
    int64_t rel=esp_timer_get_time()-epoch_us;
    if (rel<0) { ++s9c_deadline_guard; return original; }
    uint32_t phase=(uint32_t)(rel%600000LL);
    uint32_t proposal=s9b1_slots[phase/S9B1_SLOT_US];
    if(proposal>=NUM_WORKERS) { ++s9c_no_worker; return original; }
    if(!(ready&(1U<<proposal))) { ++s9c_not_ready; return original; }
    if(!(eligible&(1U<<proposal))) { ++s9c_not_eligible; return original; }
    if (proposal==(uint32_t)original) { ++s9c_equal; return original; }
    if (phase>=(600000U-2U*S9C_EXTRA_BUDGET_GUARD_US) ||
        s9c_guided_this_frame>=S9C_MAX_GUIDED_GRANTS_PER_FRAME) {
        ++s9c_deadline_guard; return original;
    }
    if ((int)proposal>highest &&
        ts_budget[highest]<(int32_t)S9C_EXTRA_BUDGET_GUARD_US) {
        ++s9c_budget_guard; return original;
    }
    ++s9c_guided;
    ++s9c_guided_this_frame;
    return (int)proposal;
#define S9F1_MAX_GUIDED_PER_FRAME 48U
static volatile bool s9f1_requested=false;
static volatile bool s9f1_active=false;

static volatile bool s9f1_guide_enabled=true;
static volatile bool s9f1_guard_enabled=true;
static volatile bool s9f1_alert=false;
static volatile bool s9f1_window_open=false; 
static volatile bool s9f1_alarm_latched=false;
static volatile uint32_t s9f1_alarm_events=0;
static uint32_t s9f1_alarm_seen=0, s9f1_alert_through=0;
static volatile uint32_t s9f1_boundaries=0,s9f1_switches=0,s9f1_guided=0;
static volatile uint32_t s9f1_equal=0,s9f1_rejected=0,s9f1_deferrals=0;
static volatile uint32_t s9f1_sleeps=0,s9f1_grant_violations=0;
static uint32_t s9f1_guided_frame=0;
static volatile uint8_t s9f1_index=255U;
static void s9f1_reset(void) {
    s9f1_active=false; s9f1_alert=false;
    s9f1_alarm_latched=false; s9f1_alarm_events=0;
    s9f1_alarm_seen=0; s9f1_alert_through=0;
    s9f1_boundaries=0; s9f1_switches=0; s9f1_guided=0;
    s9f1_equal=0; s9f1_rejected=0; s9f1_deferrals=0;
    s9f1_sleeps=0; s9f1_grant_violations=0;
    s9f1_guided_frame=0; s9f1_index=255U;
}
static inline void s9f1_chi8_sample(bool alarm) {
    if(!s9f1_requested) return;
    if(alarm && !s9f1_alarm_latched) ++s9f1_alarm_events;
    s9f1_alarm_latched=alarm;
}
static void s9f1_boundary(uint32_t frame,uint32_t rate) {
    ++s9f1_boundaries;
    s9f1_guided_frame=0;
    bool ok=s9f1_requested && rate==25U && ts_requested_random &&
            !s9c_requested && !stage7c_requested && !stage7c_active &&
            chi8_mode==CHI8_SHADOW;
    if(!ok) { s9f1_active=false; return; }
    if(s9f1_alarm_latched || s9f1_alarm_events!=s9f1_alarm_seen) {
        s9f1_alarm_seen=s9f1_alarm_events;
        s9f1_alert_through=frame+2U;
    }
    s9f1_alert=frame<=s9f1_alert_through;
    if(S9F0_BANK_COUNT<2U) { s9f1_active=false; return; }
    uint8_t prev=s9f1_index;
    uint8_t next=(prev>=S9F0_BANK_COUNT) ?
        (uint8_t)(esp_random()%S9F0_BANK_COUNT) :
        (uint8_t)((prev+1U+(esp_random()%(S9F0_BANK_COUNT-1U)))%S9F0_BANK_COUNT);
    s9f1_index=next;
    if(prev!=next) ++s9f1_switches;
    s9f1_active=true;
}
static inline int s9f1_guide(uint32_t ready,uint32_t eligible,int highest,int original) {
    if(!s9f1_guide_enabled || !s9f1_active || !s9f1_requested ||
       s9f1_index>=S9F0_BANK_COUNT)
        return original;
    int64_t rel=esp_timer_get_time()-epoch_us;
    if(rel<0 || active_rate_period_ms!=25U) { ++s9f1_rejected; return original; }
    uint32_t phase=(uint32_t)(rel%600000LL);
    uint8_t p=s9f0_expected_owner(s9f1_index,(uint16_t)(phase/S9F0_SLOT_US));
    if(p>=NUM_WORKERS || !(ready&(1U<<p)) || !(eligible&(1U<<p))) {
        ++s9f1_rejected; return original;
    }
    if((int)p==original) { ++s9f1_equal; return original; }
    if(phase>=600000U-2U*(TS_SLICE_MAX_US+TS_WCET_MARGIN_US) ||
       s9f1_guided_frame>=S9F1_MAX_GUIDED_PER_FRAME ||
       ((int)p>highest && ts_budget[highest]<(int32_t)(TS_SLICE_MAX_US+TS_WCET_MARGIN_US))) {
        ++s9f1_rejected; return original;
    }
    ++s9f1_guided; ++s9f1_guided_frame;
    return p;
}

static volatile bool s11_requested=false,s11_active=false,s11_guard=true;
/*independent guidance and pending-command protection. */
static volatile bool s11_guidance_enabled=true;
static volatile bool s11_alert=false,s11_detector_alarm=false;
static volatile bool s11_force_alert=false;
static volatile uint32_t s11_alarm_events=0;
static uint32_t s11_alarm_seen=0,s11_alert_through=0;
static volatile uint32_t s11_guided=0,s11_rejected=0,s11_deferrals=0;
static volatile uint32_t s11_violations=0,s11_switches=0,s11_boundaries=0;
static uint32_t s11_frame_guides=0;
static volatile uint8_t s11_index=255U;
static void s11_detector_observe(bool alarm) {
    if(!s11_requested)return;
    if(alarm && !s11_detector_alarm)++s11_alarm_events;
    s11_detector_alarm=alarm;
}
static void s11_boundary(uint32_t frame,uint32_t rate) {
    if(!s11_requested){s11_active=false;return;}
    ++s11_boundaries; s11_frame_guides=0;
    if(!ts_requested_random || s9f1_requested || stage7c_active ||
       stage7c_requested || s9c_requested || s9f1_window_open ||
       (rate!=20U && rate!=25U)) {
        s11_active=false; ++s11_rejected;return;
    }
    if(s11_alarm_events!=s11_alarm_seen) {
        s11_alarm_seen=s11_alarm_events;
        s11_alert_through=frame+2U;
    }
    s11_alert=s11_force_alert || frame<=s11_alert_through;
    uint8_t eligible[S11_BANK_COUNT];uint8_t count=0;
    for(uint8_t i=0U;i<S11_BANK_COUNT;++i) {
        const s11_entry_t *s=&s11_bank[i];
        if(s->period_ms!=rate)continue;
        if(s11_alert ? s->alert_ok : s->normal_ok)
            eligible[count++]=i;
    }
    if(!count){s11_active=false;++s11_rejected;return;}
    uint8_t previous=s11_index;
    uint8_t choices[S11_BANK_COUNT];uint8_t nc=0;
    for(uint8_t j=0;j<count;++j)
        if(count==1U || eligible[j]!=previous)choices[nc++]=eligible[j];
    if(!nc){s11_active=false;++s11_rejected;return;}
    s11_index=choices[esp_random()%nc];
    if(s11_index!=previous)++s11_switches;
    s11_active=true;
}
static inline int s11_guide(uint32_t ready,uint32_t eligible,int highest,int original) {
    if(!s11_guidance_enabled || !s11_active || !s11_requested || s11_index>=S11_BANK_COUNT)return original;
    int64_t rel=esp_timer_get_time()-epoch_us;
    if(rel<0){++s11_rejected;return original;}
    uint32_t phase=(uint32_t)(rel%600000LL);
    uint8_t p=s11_expected_owner(s11_index,(uint16_t)(phase/S11_SLOT_US));
    if(p>=NUM_WORKERS || !(ready&(1U<<p)) || !(eligible&(1U<<p))) {
        ++s11_rejected;return original;
    }
    if((int)p==original)return original;
    if(phase>=600000U-2U*(TS_SLICE_MAX_US+TS_WCET_MARGIN_US) ||
       s11_frame_guides>=48U ||
       ((int)p>highest && ts_budget[highest]<(int32_t)(TS_SLICE_MAX_US+TS_WCET_MARGIN_US))) {
        ++s11_rejected;return original;
    }
    ++s11_guided;++s11_frame_guides;return (int)p;
}
static void ts_dispatcher_task(void *arg)
{
    (void)arg;
    ts_recompute_budgets(CONTROL_PERIOD_MS);
    uint32_t last_period=CONTROL_PERIOD_MS;
    for (;;) {
        uint32_t ready_mask = 0;
        uint32_t pending[NUM_WORKERS];
        portENTER_CRITICAL(&ts_mux);
        for(int i=0;i<NUM_WORKERS;++i) {
            pending[i] = ts_pending[i];
            if(pending[i]) ready_mask |= (1U << i);
        }
        portEXIT_CRITICAL(&ts_mux);
        if(!ready_mask) {
            ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
            continue;
        }
        uint32_t period=active_rate_period_ms;
        if(period != last_period) {
            ts_recompute_budgets(period);
            last_period=period;
        }
        if ((ready_mask & (1U << 0)) && (ready_mask & (1U << 3)))
            ready_mask &= ~(1U << 3);
        if(((s9f1_guard_enabled && s9f1_active && s9f1_requested) ||
             (s11_guard && s11_active && s11_requested)) && s9f1_window_open &&
           (ready_mask&(1U<<4))) {
            ready_mask &= ~(1U<<4);
            if(s11_active && s11_guard)++s11_deferrals;
            else ++s9f1_deferrals;
            if(!ready_mask) {
                ++s9f1_sleeps;
                (void)ulTaskNotifyTake(pdTRUE,1U);
                continue;
            }
        }
        int highest=-1;
        for (int i=0;i<NUM_WORKERS;++i)
            if(ready_mask & (1U<<i)) { highest=i; break; }
        if(highest < 0) continue;
        uint32_t candidates=(1U<<highest);
        bool random_mode=ts_requested_random;
        if(random_mode && ts_budget[highest]>0) {
            for(int i=highest+1;i<NUM_WORKERS;++i) {
                if(!(ready_mask & (1U<<i))) continue;
                if ((NUM_WORKERS-i) >= ts_min_inv_prio[highest])
                    candidates |= (1U<<i);
                if(ts_budget[i] <= 0) break;
            }
        }
        int indices[NUM_WORKERS], count=0;
        for(int i=0;i<NUM_WORKERS;++i)
            if(candidates & (1U<<i)) indices[count++]=i;
        int selected=indices[random_mode ? (esp_random() % count) : 0];
        selected=s9c_maybe_guide(ready_mask,candidates,highest,selected);
        selected=s9f1_guide(ready_mask,candidates,highest,selected);
        selected=s11_guide(ready_mask,candidates,highest,selected);
        s9b1_observe_dispatch(ready_mask, candidates, selected);
        int32_t minimum_budget=TS_SLICE_MAX_US;
        for(int j=0;j<selected;++j) {
            if(!(ready_mask&(1U<<j))) continue;
            if(ts_budget[j] < minimum_budget) minimum_budget=ts_budget[j];
        }
        uint32_t limit=TS_SLICE_MAX_US;
        if(selected != highest && minimum_budget < (int32_t)limit)
            limit = minimum_budget > 0 ? (uint32_t)minimum_budget : 1U;
        if(random_mode && selected != highest && limit > TS_SLICE_MIN_US)
            limit=TS_SLICE_MIN_US+(esp_random()%(limit-TS_SLICE_MIN_US+1));
        if(!limit) limit=1;
        uint32_t decision=++ts_decisions;
        if(selected != highest) ++ts_inversions;
        if(s9f1_active && s9f1_guard_enabled && selected==4 && s9f1_window_open)
            ++s9f1_grant_violations;
        if(s11_active && s11_guard && selected==4 && s9f1_window_open)
            ++s11_violations;
        ts_grant_us[selected]=limit;
        xTaskNotifyGive(workers[selected].task);
        ts_ack_t ack;
        xQueueReceive(ts_ack_queue, &ack, portMAX_DELAY);
        cap_add('G', (uint8_t)selected, ack.job, ack.started_us,
                ack.ended_us, limit, ack.done);
        if(ack.idx != selected) {
            ++ts_overruns;
            ++ts_bad_acks;
        }
        if(ack.elapsed_us > limit + TS_WCET_MARGIN_US) {
            ++ts_overruns;
            ++ts_elapsed_overruns;
            ++ts_task_elapsed_overruns[selected];
            uint32_t excess = ack.elapsed_us - limit;
            if(excess > ts_max_elapsed_excess_us)
                ts_max_elapsed_excess_us = excess;
        }
        if(ack.elapsed_us > ts_runtime_us_max[selected])
            ts_runtime_us_max[selected]=ack.elapsed_us;
        for(int j=0;j<selected;++j) {
            if(ready_mask & (1U<<j)) {
                ts_budget[j] -= (int32_t)ack.elapsed_us;
                if(ts_budget[j] < 0) {
                    ++ts_overruns;
                    ++ts_budget_underflows;
                    ++ts_task_budget_underflows[j];
                }
            }
        }
        if (ack.done) {
            portENTER_CRITICAL(&ts_mux);
            if(ts_pending[selected]) --ts_pending[selected];
            portEXIT_CRITICAL(&ts_mux);
        }
        if(decision % 80 == 0) {
            char out[144];
            snprintf(out,sizeof(out),"TSDEC,%" PRIu32 ",%d,%08" PRIx32
                     ",%08" PRIx32 ",%" PRIu32 ",%" PRIu32,
                     decision, selected, ready_mask, candidates, limit,
                     ack.elapsed_us);
            enqueue_line(out);
        }
    }
}




typedef struct {
    bool valid, attacked;
    uint32_t seq, miss;
    float ref, omega, computed_v, applied_v;
    int64_t planned_us, started_us, finished_us;
    int64_t published_us; /* timestamp of protected buffer publication */
    uint32_t control_job; /* trusted evaluator metadata, not exposed to attacker */
} actuator_command_t;
static actuator_command_t pending_cmd;
static portMUX_TYPE actuator_mux = portMUX_INITIALIZER_UNLOCKED;
static bool attack_enabled = false;
static volatile uint32_t overwrite_count;
static bool inference_reset_requested = false;
static uint32_t attacker_target_period_us = TARGET_PERIOD_US;
typedef struct {
    uint64_t aai[LADDER_TARGETS];
    uint64_t aei[LADDER_TARGETS];
    uint32_t observed_jobs;
    uint32_t inferred_phase_us;
    uint32_t last_attempt_period;
    int64_t last_report_us;
    bool phase_ready, has_attempted;
} attacker_inference_t;

static const char *ladder_targets[LADDER_TARGETS] = {"CONTROL", "SAFETY", "MONITOR"};


typedef enum { TR_TX=1, TR_OWN=2, TR_LADDER=3, TR_ATTEMPT=4 } trace_kind_t;
typedef struct {
    trace_kind_t kind;
    union {
        struct {actuator_command_t c; uint32_t tx_job; int64_t read_us;} tx;
        struct {uint32_t job; int64_t planned, started, finished;
                uint64_t run[LADDER_TARGETS];} own;
        struct {uint64_t aai[LADDER_TARGETS], aei[LADDER_TARGETS];
                uint32_t periods[LADDER_TARGETS];
                uint32_t jobs, phase_us; bool ready;} ladder;
        struct {int64_t when_us; uint32_t phase_us, seq, count;
                bool success;} attempt;
    } d;
} trace_record_t;
static uint64_t valid_bits(uint32_t period_us);
static QueueHandle_t trace_queue;
static volatile uint32_t trace_drops;

static void trace_post(const trace_record_t *record)
{
    if(xQueueSend(trace_queue, record, 0) != pdTRUE) ++trace_drops;
}

static void trace_format_task(void *arg)
{
    (void)arg;
    trace_record_t rec;
    char line[172];
    for (;;) {
        if (xQueueReceive(trace_queue, &rec, portMAX_DELAY) != pdTRUE) continue;
        switch (rec.kind) {
        case TR_TX: {
            const actuator_command_t *c=&rec.d.tx.c;
            snprintf(line, sizeof(line),
                "AEW,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRId64
                ",%" PRId64 ",%u", c->seq, c->control_job,
                rec.d.tx.tx_job, c->published_us, rec.d.tx.read_us,
                (unsigned)c->attacked);
            enqueue_line(line);
            snprintf(line, sizeof(line), "ACT,%" PRIu32 ",%.4f,%.4f,%u",
                c->seq, c->computed_v, c->applied_v, (unsigned)c->attacked);
            enqueue_line(line);
            snprintf(line, sizeof(line),
                "CMD,%" PRIu32 ",%.4f,%.4f,%.4f,%" PRId64 ",%" PRId64
                ",%" PRId64 ",%" PRIu32,
                c->seq,c->ref,c->omega,c->applied_v,c->planned_us,
                c->started_us,c->finished_us,c->miss);
            enqueue_line(line);
            break;
        }
        case TR_OWN:
            snprintf(line, sizeof(line),
                "OWN,%" PRIu32 ",%" PRId64 ",%" PRId64 ",%" PRId64
                ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64,
                rec.d.own.job,rec.d.own.planned,rec.d.own.started,
                rec.d.own.finished,rec.d.own.run[0],rec.d.own.run[1],
                rec.d.own.run[2]);
            enqueue_line(line);
            break;
        case TR_LADDER:
            for (int i=0; i<LADDER_TARGETS; ++i) {
                uint64_t candidates=rec.d.ladder.aai[i] &
                    (~rec.d.ladder.aei[i]) & valid_bits(rec.d.ladder.periods[i]);
                snprintf(line,sizeof(line),
                    "LAD,%s,%" PRIu32 ",%u,%016" PRIx64 ",%016" PRIx64
                    ",%016" PRIx64 ",%" PRIu32,
                    ladder_targets[i], rec.d.ladder.periods[i], LADDER_BIN_US,
                    rec.d.ladder.aai[i],rec.d.ladder.aei[i],candidates,
                    rec.d.ladder.jobs);
                enqueue_line(line);
            }
            snprintf(line,sizeof(line),"INF,%u,%" PRIu32 ",%" PRIu32,
                (unsigned)rec.d.ladder.ready, rec.d.ladder.phase_us,
                rec.d.ladder.jobs);
            enqueue_line(line);
            break;
        case TR_ATTEMPT:
            snprintf(line,sizeof(line),"TRY,%" PRId64 ",%" PRIu32
                    ",%" PRIu32 ",%u", rec.d.attempt.when_us,
                    rec.d.attempt.phase_us,rec.d.attempt.seq,
                    (unsigned)rec.d.attempt.success);
            enqueue_line(line);
            if (rec.d.attempt.success) {
                snprintf(line,sizeof(line),"ATK,%" PRIu32 ",%" PRIu32,
                    rec.d.attempt.seq,rec.d.attempt.count);
                enqueue_line(line);
            }
            break;
        default:
            break;
        }
    }
}



static void enqueue_line(const char *s)
{
    line_t l = {0};
    snprintf(l.data, sizeof(l.data), "%s", s);
    if (xQueueSend(output_queue, &l, 0) != pdTRUE) lost_lines++;
}

static void spin_work(uint32_t duration_us)
{
    int64_t start = esp_timer_get_time();
    while ((esp_timer_get_time() - start) < duration_us) {
        __asm__ __volatile__("" ::: "memory");
    }
}

static void publish_timing(worker_t *w, release_t r,
                           int64_t started, int64_t finished)
{
    timing_t e = {
        .name = w->name, .job = r.job, .period_ms = r.period_ms,
        .planned_us = r.planned_us, .release_us = r.release_us,
        .start_us = started, .finish_us = finished,
        .miss = (uint32_t)(finished > r.planned_us +
                            (int64_t)r.period_ms * 1000),
    };
    if(e.miss) ++ts_deadline_miss;
    cap_add('J', (uint8_t)(w-workers), r.job, finished, finished,
            r.period_ms, (uint8_t)(e.miss != 0));
    if (xQueueSend(event_queue, &e, 0) != pdTRUE) lost_events++;
}


static void stage7d_raise(uint32_t seq, bool injected)
{
    portENTER_CRITICAL(&state_mux);
    if (stage7d_auto && stage7c_requested) {
        ++stage7d_events;
        stage7d_last_seq = seq;
        if (injected) ++stage7d_tested; else ++stage7d_detected;
    }
    portEXIT_CRITICAL(&state_mux);
}
static void stage7d_observe_tx(const actuator_command_t *c)
{
    if(chi8_mode==CHI8_AUTO) return;
    if (!isfinite(c->computed_v) || !isfinite(c->applied_v) ||
        fabsf(c->computed_v - c->applied_v) > STAGE7D_VOLT_TOLERANCE)
        stage7d_raise(c->seq, false);
}


static void chi8_capture_trusted(const actuator_command_t *c)
{
    portENTER_CRITICAL(&chi8_mux);
    chi8_trusted_seq=c->seq;
    /* ACT %.4f is the signal recorded by the host shadow. */
    chi8_trusted_voltage=round((double)c->computed_v*10000.0)/10000.0;
    portEXIT_CRITICAL(&chi8_mux);
}
static void chi8_observe_sensor(uint32_t seq, float omega)
{
    if (chi8_mode==CHI8_OFF) return;
    uint32_t trusted_seq;
    double prev_voltage;
    portENTER_CRITICAL(&chi8_mux);
    trusted_seq=chi8_trusted_seq;
    prev_voltage=chi8_trusted_voltage;
    portEXIT_CRITICAL(&chi8_mux);
    bool prev_valid=chi8_state.initialized && (seq==chi8_state.last_seq+1U) &&
                    trusted_seq==chi8_state.last_seq;
    (void)chi8_model_step(&chi8_state,seq,(double)omega,prev_valid,prev_voltage);
    if (chi8_trace) {
        char message[172];
        snprintf(message,sizeof(message),"CHI8,%" PRIu32 ",%.12g,%.12g,%.12g,%.12g,%u",
            seq,chi8_state.last_prediction,chi8_state.last_residual,
            chi8_state.last_z,chi8_state.last_g,(unsigned)chi8_state.alarm);
        line_t out={0};
        snprintf(out.data,sizeof(out.data),"%s",message);
        if(xQueueSend(output_queue,&out,0)!=pdTRUE) ++chi8_trace_drops;
    }
    s9c_on_chi8_sample((bool)chi8_state.alarm);
    s9f1_chi8_sample((bool)chi8_state.alarm);
    s11_detector_observe((bool)chi8_state.alarm);
    if (chi8_mode==CHI8_AUTO && chi8_state.alarm) {
        stage7d_raise(seq,false);
    }
}

static void tx_task(void *arg)
{
    worker_t *w = (worker_t *)arg;
    release_t r;
    for (;;) {
        if (xQueueReceive(w->releases, &r, portMAX_DELAY) != pdTRUE) continue;
        ts_current_job[w-workers]=r.job;
        (void)ts_wait_grant(w);
        int64_t started = esp_timer_get_time();
        int64_t grant_started = started;
        ts_run_padding(w, w->work_us, &grant_started);

        actuator_command_t c;
        int64_t read_us;
        portENTER_CRITICAL(&actuator_mux);
        read_us = esp_timer_get_time();
        c = pending_cmd;
        pending_cmd.valid = false;
        s9f1_window_open=false;
        portEXIT_CRITICAL(&actuator_mux);
        cap_add('X', 3, r.job, read_us, read_us,
                c.valid ? c.seq : UINT32_MAX, (uint8_t)c.valid);

        if (c.valid) {
            proto_last_tx_seq = c.seq;
            chi8_capture_trusted(&c);
            stage7d_observe_tx(&c);
            trace_record_t rec = {.kind=TR_TX};
            rec.d.tx.c=c;
            rec.d.tx.tx_job=r.job;
            rec.d.tx.read_us=read_us;
            trace_post(&rec);
            ++cmd_sent;
        }
        publish_timing(w, r, started, esp_timer_get_time());
        ts_send_ack(w, true, grant_started);
    }
}

static void control_task(void *arg)
{
    worker_t *w = (worker_t *)arg;
    release_t r;
    sensor_t s;
    uint32_t last_seq = UINT32_MAX;
    float integral = 0.0f;
    int64_t last_control_planned_us = 0;

    for (;;) {
        if (xQueueReceive(w->releases, &r, portMAX_DELAY) != pdTRUE) continue;
        ts_current_job[w-workers]=r.job;
        (void)ts_wait_grant(w);
        int64_t started = esp_timer_get_time();
        int64_t grant_started = started;

        float ref;
        bool reset;
        portENTER_CRITICAL(&state_mux);
        ref = setpoint;
        reset = reset_requested;
        reset_requested = false;
        portEXIT_CRITICAL(&state_mux);
        if (reset) {
            integral = 0.0f;
            last_seq = UINT32_MAX;
            last_control_planned_us = 0;
        }
        float dt = last_control_planned_us > 0 ?
                   (float)(r.planned_us - last_control_planned_us) / 1000000.0f :
                   (float)r.period_ms / 1000.0f;
        last_control_planned_us = r.planned_us;
        if (dt <= 0.0f || dt > 0.100f) dt = (float)r.period_ms / 1000.0f;

        
	bool new_sensor = xQueueReceive(sensor_queue, &s, 0) == pdTRUE;
        int64_t sensor_checked_us = esp_timer_get_time();
        if (new_sensor) proto_last_seen_seq = s.seq;
        bool valid = new_sensor && (s.seq != last_seq) &&
                     (sensor_checked_us >= s.received_us) &&
                     (sensor_checked_us - s.received_us < INPUT_MAX_AGE_US);
        if (new_sensor && !valid) ++proto_rejected_sensor_count;
        if (valid) proto_last_valid_seq = s.seq;
        float voltage = 0.0f;
        if (valid) {
            float error = ref - s.omega;
            float candidate_i = integral + MOTOR_KI * dt * error;
            float unsat = MOTOR_KP * error + candidate_i;
            /* Conditional integration anti-windup. */
            if ((unsat <= MOTOR_MAX_V && unsat >= -MOTOR_MAX_V) ||
                (unsat > MOTOR_MAX_V && error < 0.0f) ||
                (unsat < -MOTOR_MAX_V && error > 0.0f)) {
                integral = candidate_i;
            }
            voltage = MOTOR_KP * error + integral;
            if (voltage > MOTOR_MAX_V) voltage = MOTOR_MAX_V;
            if (voltage < -MOTOR_MAX_V) voltage = -MOTOR_MAX_V;
            last_seq = s.seq;
        }

        
        ts_run_padding(w, CONTROL_WCET_PAD_US, &grant_started);
        int64_t finished = esp_timer_get_time();
        publish_timing(w, r, started, finished);
        if (valid) {
            actuator_command_t c = {
                .valid = true, .attacked = false,
                .seq = s.seq,
                .miss = (uint32_t)(finished > r.planned_us +
                                   (int64_t)r.period_ms * 1000),
                .ref = ref, .omega = s.omega,
                .computed_v = voltage, .applied_v = voltage,
                .planned_us = r.planned_us,
                .started_us = started, .finished_us = finished,
            };
            portENTER_CRITICAL(&actuator_mux);
            c.published_us = esp_timer_get_time();
            c.control_job = r.job;
            pending_cmd = c;
            s9f1_window_open=true;
            portEXIT_CRITICAL(&actuator_mux);
            cap_add('P', 0, r.job, c.published_us, c.published_us,
                    c.seq, 1);
        }
        ts_send_ack(w, true, grant_started);
    }
}

static uint64_t bin_bit(int64_t time_us, uint32_t period_us)
{
    uint32_t bin = (uint32_t)((time_us / LADDER_BIN_US) %
                              (period_us / LADDER_BIN_US));
    return UINT64_C(1) << bin;
}

static uint64_t valid_bits(uint32_t period_us)
{
    uint32_t n = period_us / LADDER_BIN_US;
    return (UINT64_C(1) << n) - 1;
}

static int only_one_bit(uint64_t x)
{
    return x && !(x & (x-1));
}

static int first_set_bit(uint64_t x)
{
    for (int i = 0; i < 60; ++i) if (x & (UINT64_C(1) << i)) return i;
    return -1;
}

static void report_ladders(attacker_inference_t *inf,
                           const uint32_t periods[LADDER_TARGETS])
{
    trace_record_t rec = {.kind=TR_LADDER};
    for(int i=0;i<LADDER_TARGETS;++i) {
        rec.d.ladder.aai[i]=inf->aai[i];
        rec.d.ladder.aei[i]=inf->aei[i];
        rec.d.ladder.periods[i]=periods[i];
    }
    rec.d.ladder.jobs=inf->observed_jobs;
    rec.d.ladder.phase_us=inf->inferred_phase_us;
    rec.d.ladder.ready=inf->phase_ready;
    trace_post(&rec);
}

static void untrusted_job(worker_t *w, release_t r,
                          attacker_inference_t *inf, int64_t *grant_start)
{
    bool clear, armed;
    uint32_t target_period_us;
    portENTER_CRITICAL(&actuator_mux);
    clear = inference_reset_requested;
    inference_reset_requested = false;
    armed = attack_enabled;
    target_period_us = attacker_target_period_us;
    portEXIT_CRITICAL(&actuator_mux);
    if (clear) memset(inf, 0, sizeof(*inf));

    
    const uint32_t periods[LADDER_TARGETS] = {
        target_period_us, ladder_periods[1], ladder_periods[2]
    };
    int64_t started = esp_timer_get_time();
    uint64_t own_run[LADDER_TARGETS] = {0};
    
    for (int i = 0; i < LADDER_TARGETS; ++i)
        inf->aai[i] |= bin_bit(r.planned_us, periods[i]);

    
    ts_run_attacker(w, own_run, periods, grant_start);
    int64_t finished = esp_timer_get_time();
    for (int i = 0; i < LADDER_TARGETS; ++i)
        inf->aei[i] |= own_run[i];
    ++inf->observed_jobs;

    trace_record_t own = {.kind=TR_OWN};
    own.d.own.job=r.job;
    own.d.own.planned=r.planned_us;
    own.d.own.started=started;
    own.d.own.finished=finished;
    for(int i=0;i<LADDER_TARGETS;++i) own.d.own.run[i]=own_run[i];
    trace_post(&own);

    
    uint64_t c = inf->aai[0] & (~inf->aei[0]) & valid_bits(target_period_us);
    inf->phase_ready = inf->observed_jobs >= LEARNING_MIN_JOBS && only_one_bit(c);
    if (inf->phase_ready)
        inf->inferred_phase_us = (uint32_t)first_set_bit(c) * LADDER_BIN_US;
    else
        inf->inferred_phase_us = 0;

    if (inf->last_report_us == 0 || finished - inf->last_report_us >= 1000000) {
        report_ladders(inf, periods);
        inf->last_report_us = finished;
    }

    
    if (armed && inf->phase_ready) {
        int64_t offset = ((finished - (int64_t)inf->inferred_phase_us) %
                           target_period_us + target_period_us) % target_period_us;
        uint32_t period = (uint32_t)((finished -
                           (int64_t)inf->inferred_phase_us) / target_period_us);
        if (offset >= ATTACK_START_US && offset < ATTACK_END_US &&
            (!inf->has_attempted || period != inf->last_attempt_period)) {
            inf->last_attempt_period = period;
            inf->has_attempted = true;
            bool corrupted = false;
            uint32_t seq = UINT32_MAX;
            int64_t attempt_us;
            portENTER_CRITICAL(&actuator_mux);
            attempt_us = esp_timer_get_time();
            if (pending_cmd.valid && !pending_cmd.attacked) {
                pending_cmd.applied_v = -MOTOR_MAX_V;
                pending_cmd.attacked = true;
                seq = pending_cmd.seq;
                overwrite_count++;
                corrupted = true;
            }
            portEXIT_CRITICAL(&actuator_mux);
            trace_record_t attempt = {.kind=TR_ATTEMPT};
            attempt.d.attempt.when_us=attempt_us;
            attempt.d.attempt.phase_us=inf->inferred_phase_us;
            attempt.d.attempt.seq=seq;
            attempt.d.attempt.success=corrupted;
            attempt.d.attempt.count=overwrite_count;
            trace_post(&attempt);
        }
    }
}

static void dummy_task(void *arg)
{
    worker_t *w = (worker_t *)arg;
    release_t r;
    attacker_inference_t inf = {0};
    for (;;) {
        if (xQueueReceive(w->releases, &r, portMAX_DELAY) != pdTRUE) continue;
        ts_current_job[w-workers]=r.job;
        (void)ts_wait_grant(w);
        int64_t started = esp_timer_get_time();
        int64_t grant_started = started;
        if (strcmp(w->name, "UNTRUSTED") == 0) {
            untrusted_job(w, r, &inf, &grant_started);
        } else {
            ts_run_padding(w, w->work_us, &grant_started);
        }
        publish_timing(w, r, started, esp_timer_get_time());
        ts_send_ack(w, true, grant_started);
    }
}

static uint32_t stage7c_frame_commit(uint32_t frame, int64_t planned,
                                     uint32_t fallback_rate)
{
    bool requested;
    uint16_t victim;
    portENTER_CRITICAL(&state_mux);
    requested = stage7c_requested;
    victim = stage7c_victim;
    portEXIT_CRITICAL(&state_mux);
    bool was_active = stage7c_active;
    if (!requested) {
        if (was_active) {
            stage7c_active = false;
            stage7c_current = MAARS_NONE;
            ts_requested_random = stage7c_prior_ts_random;
            stage7c_last_frame = frame;
            enqueue_line("MAARSAPPLY,DEMO,DISABLED");
        }
        return fallback_rate;
    }
    
    bool pending = false;
    portENTER_CRITICAL(&ts_mux);
    for (int i = 0; i < NUM_WORKERS; ++i) {
        if (ts_pending[i] != 0) pending = true;
    }
    portEXIT_CRITICAL(&ts_mux);
    if (pending) {
        stage7c_last_rc = -3;
        ++stage7c_blocks;
        stage7c_last_frame = frame;
        return was_active ? (stage7c_current == 1 ? 25U : 20U)
                          : (uint32_t)active_rate_period_ms;
    }
    if (!was_active) stage7c_prior_ts_random = ts_requested_random;
    uint16_t next = MAARS_NONE;
    uint16_t previous = stage7c_current;
    int rc = maars_schedsel(&stage7c_demo_catalog, previous, victim,
                           stage7b_rng, NULL, &next);
    stage7c_last_rc = rc;
    stage7c_last_frame = frame;
    if (rc == 0) {
        stage7c_current = next;
        stage7c_active = true;
        ++stage7c_commits;
    } else {
        ++stage7c_blocks;
    }
    
    if (!stage7c_active) return (uint32_t)active_rate_period_ms;
    uint32_t actual_rate = (stage7c_current == 1) ? 25U : 20U;
    ts_requested_random = true;
    
    char out[160];
    snprintf(out, sizeof(out),
        "MAARSAPPLY,DEMO,%" PRIu32 ",%u,%u,%u,%d,%" PRIu32 ",1,%" PRId64,
        frame, (unsigned)victim, (unsigned)previous,
        (unsigned)stage7c_current, rc, actual_rate, planned);
    line_t entry = {0};
    snprintf(entry.data, sizeof(entry.data), "%s", out);
    if (xQueueSend(output_queue, &entry, 0) != pdTRUE) ++cfg_log_drops;
    return actual_rate;
}


static void stage7d_auto_boundary(uint32_t frame)
{
    bool enabled, requested;
    uint32_t events, seq;
    uint16_t victim;
    bool emit = false;
    portENTER_CRITICAL(&state_mux);
    enabled = stage7d_auto;
    requested = stage7c_requested;
    if (enabled && requested) {
        events = stage7d_events;
        seq = stage7d_last_seq;
        if (events != stage7d_seen) {
            stage7d_seen = events;
            stage7d_alert_through = frame + STAGE7D_ALERT_HOLD_FRAMES;
        }
        victim = frame <= stage7d_alert_through ? 1U : 0U;
        if (stage7c_victim != victim) {
            stage7c_victim = victim;
            emit = true;
        }
    } else {
        events = stage7d_events;
        seq = stage7d_last_seq;
        victim = stage7c_victim;
    }
    portEXIT_CRITICAL(&state_mux);
    if (emit) {
        char msg[140];
        snprintf(msg, sizeof(msg), "MAARSAUTO,FRAME,%" PRIu32 ",%u,%" PRIu32 ",%" PRIu32,
                 frame, (unsigned)victim, events, seq);
        line_t entry = {0};
        snprintf(entry.data, sizeof(entry.data), "%s", msg);
        if (xQueueSend(output_queue, &entry, 0) != pdTRUE) ++cfg_log_drops;
    }
}

/* 1 ms timer for periodic worker releases. */
static void on_grid_tick(void *arg)
{
    (void)arg;
    slot_index++;
    uint32_t local_slot = slot_index % SUPERFRAME_MS;
    int64_t planned = epoch_us + (int64_t)slot_index * GRID_US;
    int64_t actual = esp_timer_get_time();
    
    if (local_slot == 0) {
        rate_mode_t choice;
        portENTER_CRITICAL(&state_mux);
        choice = requested_rate_mode;
        portEXIT_CRITICAL(&state_mux);
        uint32_t old_rate = active_rate_period_ms;
        uint32_t new_rate = choice == RATE_FIXED_20 ? CONTROL_PERIOD_MS :
                            choice == RATE_FIXED_25 ? ALT_CONTROL_PERIOD_MS :
                            ((superframe_number & 1U) ? ALT_CONTROL_PERIOD_MS : CONTROL_PERIOD_MS);
        stage7d_auto_boundary(superframe_number + 1U);
        new_rate = stage7c_frame_commit(superframe_number + 1U, planned, new_rate);
        active_rate_period_ms = new_rate;
        s9c_frame_boundary(superframe_number + 1U, new_rate);
        s9f1_boundary(superframe_number + 1U, new_rate);
        s11_boundary(superframe_number + 1U, new_rate);
        ts_recompute_budgets(new_rate);
        if (new_rate != old_rate) ++rate_switch_count;
        ++superframe_number;
        stage7b_shadow_boundary(superframe_number, planned);
        char msg[120];
        snprintf(msg, sizeof(msg), "CFG,%" PRIu32 ",%" PRIu32 ",%u,%" PRId64,
                 superframe_number, new_rate, (unsigned)choice, planned);
        line_t entry = {0};
        snprintf(entry.data, sizeof(entry.data), "%s", msg);
        if (xQueueSend(output_queue, &entry, 0) != pdTRUE) ++cfg_log_drops;
    }
    if (local_slot == 0)
        cap_boundary(planned, active_rate_period_ms, superframe_number);
    uint32_t control_period = active_rate_period_ms;
    for (int i = 0; i < NUM_WORKERS; ++i) {
        worker_t *w = &workers[i];
        uint32_t period = i == 0 || i == 3 ? control_period : w->period_ms;
        uint32_t release_offset = w->offset_ms;
        if (local_slot % period != release_offset) continue;
        release_t r = {planned, actual, w->next_job++, period};
        if (xQueueSend(w->releases, &r, 0) != pdTRUE) {
            w->dropped++;
            cap_add('D', (uint8_t)i, r.job, r.planned_us,
                    r.release_us, period, 0);
        } else {
            cap_add('R', (uint8_t)i, r.job, r.planned_us,
                    r.release_us, period, 1);
            portENTER_CRITICAL(&ts_mux);
            if(ts_pending[i]) ++ts_release_overlaps;
            ++ts_pending[i];
            ts_budget[i]=ts_budget_max[i];
            portEXIT_CRITICAL(&ts_mux);
            if (ts_dispatcher_handle) xTaskNotifyGive(ts_dispatcher_handle);
        }
    }
}

/* Only this task writes to the console: command and telemetry lines do not interleave*/
static void writer_task(void *arg)
{
    (void)arg;
    line_t line;
    for (;;) {
        if (xQueueReceive(output_queue, &line, portMAX_DELAY) == pdTRUE) {
            printf("%s\n", line.data);
        }
    }
}

static void event_logger_task(void *arg)
{
    (void)arg;
    timing_t t;
    char line[172];
    for (;;) {
        if (xQueueReceive(event_queue, &t, portMAX_DELAY) != pdTRUE) continue;
        uint32_t stride = (strcmp(t.name, "CONTROL") == 0) ? 5 :
                          (strcmp(t.name, "SAFETY") == 0) ? 2 :
                          (strcmp(t.name, "MONITOR") == 0) ? 2 :
                          (strcmp(t.name, "TX") == 0) ? 5 : 5;
        if (t.job % stride != 0 && !t.miss) continue;
        snprintf(line, sizeof(line),
                 "EVT,%s,%" PRIu32 ",%" PRIu32 ",%" PRId64 ",%" PRId64
                 ",%" PRId64 ",%" PRId64 ",%" PRIu32,
                 t.name, t.job, t.period_ms, t.planned_us, t.release_us,
                 t.start_us, t.finish_us, t.miss);
        enqueue_line(line);
    }
}

static void ts_clear_diagnostics(void)
{
    ts_bad_acks=0;
    ts_elapsed_overruns=0;
    ts_budget_underflows=0;
    ts_max_elapsed_excess_us=0;
    for(int i=0; i<NUM_WORKERS; ++i) {
        ts_task_elapsed_overruns[i]=0;
        ts_task_budget_underflows[i]=0;
        ts_runtime_us_max[i]=0;
    }
}

static void parse_input(char *line)
{
    
    if(strcmp(line,"S11,ON")==0) {
        if(s9f1_requested || s9c_requested || stage7c_requested ||
           stage7c_active || !ts_requested_random || chi8_mode==CHI8_OFF) {
            enqueue_line("ERR,S11,NEED_TS_CHI8_NO_S9F_S9C_STAGE7C");return;
        }
        s11_active=false;s11_requested=true;s11_guard=true;s11_guidance_enabled=true;
        s11_force_alert=false;s11_alarm_events=0;s11_alarm_seen=0;
        s11_detector_alarm=false;s11_alert_through=0;s11_index=255U;
        s11_guided=0;s11_rejected=0;s11_deferrals=0;s11_violations=0;
        s11_switches=0;s11_boundaries=0;
        enqueue_line("ACK,S11,ON,MODEL_GUIDANCE");return;
    }
    
    if(strcmp(line,"S11,MODE,GUIDE")==0 ||
       strcmp(line,"S11,MODE,GUARD")==0 ||
       strcmp(line,"S11,MODE,BOTH")==0) {
        if(!s11_requested) {enqueue_line("ERR,S11,MODE,NOT_ENABLED");return;}
        if(strcmp(line,"S11,MODE,GUIDE")==0) {
            s11_guidance_enabled=true;s11_guard=false;
            enqueue_line("ACK,S11,MODE,GUIDE,GUIDANCE=1,GUARD=0");
        } else if(strcmp(line,"S11,MODE,GUARD")==0) {
            s11_guidance_enabled=false;s11_guard=true;
            enqueue_line("ACK,S11,MODE,GUARD,GUIDANCE=0,GUARD=1");
        } else {
            s11_guidance_enabled=true;s11_guard=true;
            enqueue_line("ACK,S11,MODE,BOTH,GUIDANCE=1,GUARD=1");
        }
        return;
    }
    if(strcmp(line,"S11,OFF")==0) {
        if(s9f1_window_open) {enqueue_line("ERR,S11,COMMAND_PENDING");return;}
        s11_requested=false;s11_active=false;
        enqueue_line("ACK,S11,OFF");return;
    }
    if(strcmp(line,"S11,ALERT,CONTROL")==0) {
        s11_force_alert=true;enqueue_line("ACK,S11,ALERT,CONTROL,FORCED_LAB");return;
    }
    if(strcmp(line,"S11,ALERT,CLEAR")==0) {
        s11_force_alert=false;enqueue_line("ACK,S11,ALERT,CLEAR");return;
    }
    if(strcmp(line,"S11,STATUS")==0) {
        char out[172];
        snprintf(out,sizeof(out),
             "S11STAT,%u,%u,%u,%u,%u,%u,%" PRIu32 ",%" PRIu32
             ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32,
             (unsigned)s11_requested,(unsigned)s11_active,
             (unsigned)active_rate_period_ms,(unsigned)s11_index,
             (unsigned)s11_alert,(unsigned)s11_guard,
             s11_boundaries,s11_switches,s11_guided,s11_rejected,
             s11_deferrals,s11_violations,s11_alarm_events);
        enqueue_line(out);return;
    }

        if(strcmp(line,"S9F,ON")==0) {
        if(s11_requested || active_rate_period_ms!=25U || !ts_requested_random ||
           stage7c_requested || stage7c_active || s9c_requested ||
           chi8_mode!=CHI8_SHADOW) {
            enqueue_line("ERR,S9F,NEED_TS25_CHI8_SHADOW_NO_S9C"); return;
        }
        s9f1_requested=false; s9f1_reset();
        s9f1_guide_enabled=true; s9f1_guard_enabled=true;
        s9f1_requested=true;
        enqueue_line("ACK,S9F,REQUESTED_MODEL_ONLY"); return;
    }
    
    if(strcmp(line,"S9F,MODE,BOTH")==0 ||
       strcmp(line,"S9F,MODE,GUIDE")==0 ||
       strcmp(line,"S9F,MODE,GUARD")==0) {
        if(!s9f1_requested || s9f1_active) {
            enqueue_line("ERR,S9F,MODE,ONLY_BEFORE_FIRST_BOUNDARY"); return;
        }
        s9f1_guide_enabled=strcmp(line,"S9F,MODE,GUARD")!=0;
        s9f1_guard_enabled=strcmp(line,"S9F,MODE,GUIDE")!=0;
        enqueue_line(strcmp(line,"S9F,MODE,BOTH")==0 ? "ACK,S9F,MODE,BOTH" :
                     strcmp(line,"S9F,MODE,GUIDE")==0 ? "ACK,S9F,MODE,GUIDE" :
                     "ACK,S9F,MODE,GUARD"); return;
    }
    if(strcmp(line,"S9F,OFF")==0) {
        s9f1_requested=false; s9f1_active=false;
        enqueue_line("ACK,S9F,OFF"); return;
    }
    if(strcmp(line,"S9F,MODE,STATUS")==0) {
        char response[64];
        snprintf(response,sizeof(response),"S9FMODE,%u,%u,%u,%u",
                 (unsigned)s9f1_guide_enabled,(unsigned)s9f1_guard_enabled,
                 (unsigned)s9f1_requested,(unsigned)s9f1_active);
        enqueue_line(response); return;
    }
    if(strcmp(line,"S9F,STATUS")==0) {
        char out[172];
        uint8_t i=s9f1_index;
        const char *id=(i<S9F0_BANK_COUNT)?s9f0_bank[i].id:"NONE";
        const char *sha=(i<S9F0_BANK_COUNT)?s9f0_bank[i].sha256:"000000000000";
        snprintf(out,sizeof(out),
           "S9FSTAT,%u,%u,%u,%u,%s,%.12s,%" PRIu32 ",%" PRIu32
           ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
           ",%" PRIu32 ",%" PRIu32 ",%" PRIu32,
           (unsigned)s9f1_requested,(unsigned)s9f1_active,
           (unsigned)s9f1_alert,(unsigned)i,id,sha,
           s9f1_boundaries,s9f1_switches,s9f1_guided,s9f1_equal,
           s9f1_rejected,s9f1_deferrals,s9f1_sleeps,
           s9f1_alarm_events,s9f1_grant_violations);
        enqueue_line(out); return;
    }

    
    if (strcmp(line,"S9C,ON")==0) {
        if (active_rate_period_ms!=25U || !ts_requested_random ||
            stage7c_requested || stage7c_active || s9f1_requested || chi8_mode!=CHI8_SHADOW) {
            enqueue_line("ERR,S9C,NEED_TS25_CHI8_SHADOW_NO_DEMO"); return;
        }
        s9c_requested=false;
        s9c_lab_active=false;
        s9c_reset_counters();
        s9c_requested=true;
        enqueue_line("ACK,S9C,REQUESTED_LAB_ONLY"); return;
    }
    if (strcmp(line,"S9C,OFF")==0) {
        s9c_requested=false;
        s9c_lab_active=false;
        s9c_alert=false;
        enqueue_line("ACK,S9C,OFF"); return;
    }
    if (strcmp(line,"S9C,STATUS")==0) {
        char out[172];
        snprintf(out,sizeof(out),
          "S9CSTAT,%u,%u,%u,%s,%.12s,%" PRIu32 ",%" PRIu32
          ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
          ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
          ",%" PRIu32,
          (unsigned)s9c_requested,(unsigned)s9c_lab_active,(unsigned)s9c_alert,
          S9B1_CANDIDATE_ID,S9B1_CANDIDATE_SHA,
          s9c_boundary_count,s9c_guided,s9c_equal,s9c_not_ready,
          s9c_not_eligible,s9c_deadline_guard,s9c_budget_guard,
          s9c_no_worker,s9c_alert_fallback,s9c_mode_fallback,s9c_alarm_events);
        enqueue_line(out); return;
    }

    
    if (strcmp(line, "S9SH,ON") == 0) {
        if(active_rate_period_ms != 25U) {
            enqueue_line("ERR,S9SH,RATE_NOT_25"); return;
        }
        if(stage7c_requested || stage7c_active) {
            enqueue_line("ERR,S9SH,DEMO_OWNS_POLICY"); return;
        }
        s9b1_enabled=false;
        s9b1_reset_counts();
        s9b1_enabled=true;
        enqueue_line("ACK,S9SH,ON"); return;
    }
    if (strcmp(line, "S9SH,OFF") == 0) {
        s9b1_enabled=false;
        enqueue_line("ACK,S9SH,OFF"); return;
    }
    if (strcmp(line, "S9SH,RESET") == 0) {
        s9b1_enabled=false;
        s9b1_reset_counts();
        enqueue_line("ACK,S9SH,RESET"); return;
    }
    if (strcmp(line, "S9SH,STATUS") == 0) {
        char out[172];
        snprintf(out,sizeof(out),
                 "S9SHSTAT,%u,%s,%.12s,%" PRIu32 ",%" PRIu32 ",%" PRIu32
                 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
                 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
                 ",%" PRIu32,
                 (unsigned)s9b1_enabled,S9B1_CANDIDATE_ID,S9B1_CANDIDATE_SHA,
                 s9b1_decisions,s9b1_nonworker_slots,s9b1_unready_proposals,
                 s9b1_budget_blocked,s9b1_runnable_proposals,s9b1_matches,s9b1_mismatches,
                 s9b1_rate_skips,s9b1_last_frame,s9b1_last_slot,
                 s9b1_last_proposed,s9b1_last_actual);
        enqueue_line(out); return;
    }

    if (strcmp(line, "CHI8,STATUS") == 0) {
        char msg[172];
        snprintf(msg,sizeof(msg),"CHI8STAT,%u,%" PRIu32 ",%" PRIu32 ",%" PRIu32
            ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%u,%.10g,%u",
            (unsigned)chi8_mode,chi8_state.samples,chi8_state.alarms,
            chi8_state.resets,chi8_state.missing_voltage,chi8_trace_drops,
            chi8_state.initialized?chi8_state.last_seq:UINT32_MAX,
            chi8_state.quiet,chi8_state.last_g,(unsigned)chi8_state.alarm);
        enqueue_line(msg);
        return;
    }
    if (strcmp(line,"CHI8,TRACE,ON")==0 || strcmp(line,"CHI8,TRACE,OFF")==0) {
        chi8_trace=strcmp(line,"CHI8,TRACE,ON")==0;
        enqueue_line(chi8_trace?"ACK,CHI8,TRACE,ON":"ACK,CHI8,TRACE,OFF");
        return;
    }
    if (strcmp(line,"CHI8,RESET")==0) {
        memset(&chi8_state,0,sizeof(chi8_state));
        chi8_trace_drops=0;
        portENTER_CRITICAL(&chi8_mux);
        chi8_trusted_seq=UINT32_MAX;
        chi8_trusted_voltage=0.0;
        portEXIT_CRITICAL(&chi8_mux);
        enqueue_line("ACK,CHI8,RESET");
        return;
    }
    if (strcmp(line,"CHI8,OFF")==0 || strcmp(line,"CHI8,SHADOW")==0 ||
        strcmp(line,"CHI8,AUTO")==0) {
        bool auto_on=strcmp(line,"CHI8,AUTO")==0;
        if(auto_on && (!stage7c_requested || !stage7d_auto)) {
            enqueue_line("ERR,CHI8,REQUIRES_DEMO_AUTO"); return;
        }
        chi8_mode=auto_on?CHI8_AUTO:
                  strcmp(line,"CHI8,SHADOW")==0?CHI8_SHADOW:CHI8_OFF;
        memset(&chi8_state,0,sizeof(chi8_state));
        chi8_trace_drops=0;
        portENTER_CRITICAL(&chi8_mux);
        chi8_trusted_seq=UINT32_MAX;
        chi8_trusted_voltage=0.0;
        portEXIT_CRITICAL(&chi8_mux);
        enqueue_line(auto_on?"ACK,CHI8,AUTO":
                     chi8_mode==CHI8_SHADOW?"ACK,CHI8,SHADOW":"ACK,CHI8,OFF");
        return;
    }

    if (strcmp(line, "PING") == 0) {
        enqueue_line("PONG,MAARS_STAGE2,20");
        return;
    }
    if (strcmp(line, "INFO") == 0) {
        enqueue_line("INFO,MAARS_STAGE5D,LADDER=AAI_AEI,AEW=MEASURED,TASKSHUFFLER=COOPERATIVE,CAPTURE=ONE_FRAME");
        return;
    }
    if (strcmp(line, "CAP,ARM") == 0) {
        bool ok=false;
        portENTER_CRITICAL(&cap_mux);
        if (cap_state != CAP_ACTIVE && cap_state != CAP_ARMED) {
            cap_state=CAP_ARMED; cap_count=0; cap_lost=0;
            ok=true;
        }
        portEXIT_CRITICAL(&cap_mux);
        enqueue_line(ok ? "ACK,CAP,ARM" : "ERR,CAP,BUSY");
        return;
    }
    if (strcmp(line, "CAP,STATUS") == 0) {
        char out[172];
        portENTER_CRITICAL(&cap_mux);
        cap_state_t state=cap_state;
        uint32_t count=cap_count, loss=cap_lost, frame=cap_frame, period=cap_period;
        int64_t begin=cap_begin_us, end=cap_end_us;
        portEXIT_CRITICAL(&cap_mux);
        snprintf(out,sizeof(out),"CAPSTAT,%u,%" PRIu32 ",%" PRIu32
                 ",%" PRIu32 ",%" PRIu32 ",%" PRId64 ",%" PRId64,
                 (unsigned)state,count,loss,frame,period,begin,end);
        enqueue_line(out);
        return;
    }
    if (strncmp(line, "CAP,READ,", 9)==0) {
        unsigned offset=0, amount=0;
        char tail;
        if (sscanf(line+9,"%u,%u%c",&offset,&amount,&tail)!=2 ||
            amount<1 || amount>CAP_READ_LIMIT) {
            enqueue_line("ERR,CAP,RANGE"); return;
        }
        
        if (cap_state!=CAP_DONE) {
            enqueue_line("ERR,CAP,NOT_DONE"); return;
        }
        uint32_t stop=offset+amount;
        if (stop<offset || stop>cap_count) {
            enqueue_line("ERR,CAP,RANGE"); return;
        }
        char out[172];
        for(uint32_t i=offset;i<stop;++i) {
            const cap_record_t *r=&cap_records[i];
            snprintf(out,sizeof(out),
                     "CAPREC,%" PRIu32 ",%c,%u,%" PRIu32 ",%" PRId64
                     ",%" PRId64 ",%" PRIu32 ",%u",
                     i,(char)r->kind,(unsigned)r->worker,r->job,
                     r->start_us,r->end_us,r->arg,(unsigned)r->flag);
            enqueue_line(out);
        }
        snprintf(out,sizeof(out),"CAPEND,%u,%u",offset,amount);
        enqueue_line(out);
        return;
    }
    if (strcmp(line, "MAARS,DEMO,AUTO,ON") == 0) {
        portENTER_CRITICAL(&state_mux);
        bool allowed = stage7c_requested;
        if (allowed) {
            stage7d_auto = true;
            stage7d_seen = stage7d_events;
            stage7d_alert_through = 0;
            stage7c_victim = 0;
        }
        portEXIT_CRITICAL(&state_mux);
        enqueue_line(allowed ? "ACK,MAARS,DEMO,AUTO,ON" : "ERR,MAARS,DEMO_NOT_REQUESTED");
        return;
    }
    if (strcmp(line, "MAARS,DEMO,AUTO,OFF") == 0) {
        portENTER_CRITICAL(&state_mux);
        stage7d_auto = false;
        if(chi8_mode==CHI8_AUTO) chi8_mode=CHI8_SHADOW;
        stage7c_victim = 0;
        portEXIT_CRITICAL(&state_mux);
        enqueue_line("ACK,MAARS,DEMO,AUTO,OFF");
        return;
    }
    if (strcmp(line, "MAARS,DEMO,AUTO,TEST") == 0) {
        portENTER_CRITICAL(&state_mux);
        bool allowed = stage7d_auto && stage7c_requested;
        portEXIT_CRITICAL(&state_mux);
        if (!allowed) { enqueue_line("ERR,MAARS,AUTO_NOT_ENABLED"); return; }
        stage7d_raise(UINT32_MAX, true);
        enqueue_line("ACK,MAARS,DEMO,AUTO,TEST_ONLY");
        return;
    }
    if (strcmp(line, "MAARS,DEMO,AUTO,STATUS") == 0) {
        bool enabled;
        uint32_t events, seq, through, detected, tested;
        uint16_t victim;
        portENTER_CRITICAL(&state_mux);
        enabled = stage7d_auto;
        events = stage7d_events;
        seq = stage7d_last_seq;
        through = stage7d_alert_through;
        detected = stage7d_detected;
        tested = stage7d_tested;
        victim = stage7c_victim;
        portEXIT_CRITICAL(&state_mux);
        char msg[164];
        snprintf(msg, sizeof(msg), "MAARSAUTOSTAT,%u,%" PRIu32 ",%" PRIu32 ",%" PRIu32
                 ",%u,%" PRIu32 ",%" PRIu32,
                 (unsigned)enabled, events, seq, through, (unsigned)victim,
                 detected, tested);
        enqueue_line(msg);
        return;
    }
    if (strcmp(line, "MAARS,DEMO,ON") == 0) {
        if (stage7b_shadow_enabled) { enqueue_line("ERR,MAARS,SHADOW_ACTIVE"); return; }
        portENTER_CRITICAL(&state_mux);
        stage7c_requested = true;
        stage7c_victim = 0;
        portEXIT_CRITICAL(&state_mux);
        enqueue_line("ACK,MAARS,DEMO,REQUESTED_ON");
        return;
    }
    if (strcmp(line, "MAARS,DEMO,OFF") == 0) {
        portENTER_CRITICAL(&state_mux);
        stage7c_requested = false;
        if(chi8_mode==CHI8_AUTO) chi8_mode=CHI8_SHADOW;
        stage7d_auto = false;
        stage7c_victim = 0;
        portEXIT_CRITICAL(&state_mux);
        enqueue_line("ACK,MAARS,DEMO,REQUESTED_OFF");
        return;
    }
    if (strcmp(line, "MAARS,DEMO,NORMAL") == 0 ||
        strcmp(line, "MAARS,DEMO,ALERT,CONTROL") == 0 ||
        strcmp(line, "MAARS,DEMO,ALERT,SAFETY") == 0) {
        if (stage7d_auto) { enqueue_line("ERR,MAARS,AUTO_OWNS_FLAG"); return; }
        uint16_t flag = strcmp(line, "MAARS,DEMO,NORMAL") == 0 ? 0 :
                        strcmp(line, "MAARS,DEMO,ALERT,CONTROL") == 0 ? 1 : 2;
        portENTER_CRITICAL(&state_mux);
        stage7c_victim = flag;
        portEXIT_CRITICAL(&state_mux);
        enqueue_line("ACK,MAARS,DEMO,FLAG");
        return;
    }
    if (strcmp(line, "MAARS,DEMO,LIST") == 0) {
        for (int j = 0; j < 2; ++j) {
            char out[96];
            snprintf(out, sizeof(out), "MAARSDEMOLABEL,%d,%s", j, stage7c_labels[j]);
            enqueue_line(out);
        }
        return;
    }
    if (strcmp(line, "MAARS,DEMO,STATUS") == 0) {
        bool requested;
        uint16_t victim;
        portENTER_CRITICAL(&state_mux);
        requested = stage7c_requested;
        victim = stage7c_victim;
        portEXIT_CRITICAL(&state_mux);
        char out[160];
        snprintf(out, sizeof(out),
            "MAARSDEMOSTAT,%u,%u,%u,%u,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%d,%" PRIu32 ",%u",
            (unsigned)requested, (unsigned)stage7c_active, (unsigned)victim,
            (unsigned)stage7c_current, stage7c_last_frame,
            stage7c_commits, stage7c_blocks, stage7c_last_rc,
            active_rate_period_ms, (unsigned)ts_requested_random);
        enqueue_line(out);
        return;
    }
    if (strcmp(line, "MAARS,SHADOW,ON") == 0 ||
        strcmp(line, "MAARS,SHADOW,OFF") == 0) {
        bool enabled = strcmp(line, "MAARS,SHADOW,ON") == 0;
        if (enabled && (stage7c_requested || stage7c_active)) { enqueue_line("ERR,MAARS,DEMO_ACTIVE"); return; }
        portENTER_CRITICAL(&state_mux);
        stage7b_shadow_enabled = enabled;
        portEXIT_CRITICAL(&state_mux);
        enqueue_line(enabled ? "ACK,MAARS,SHADOW,ON" : "ACK,MAARS,SHADOW,OFF");
        return;
    }
    if (strcmp(line, "MAARS,FLAG,NORMAL") == 0) {
        portENTER_CRITICAL(&state_mux);
        stage7b_requested_victim = 0;
        portEXIT_CRITICAL(&state_mux);
        enqueue_line("ACK,MAARS,FLAG,NORMAL");
        return;
    }
    if (strncmp(line, "MAARS,FLAG,", 11) == 0) {
        const char *name = line + 11;
        uint16_t victim = 0;
        for (uint16_t j = 0; j < stage7b_catalog.victim_count; ++j) {
            if (strcmp(name, stage7b_victim_names[j]) == 0) {
                victim = (uint16_t)(j+1); break;
            }
        }
        if (!victim) { enqueue_line("ERR,MAARS,UNKNOWN_VICTIM"); return; }
        portENTER_CRITICAL(&state_mux);
        stage7b_requested_victim = victim;
        portEXIT_CRITICAL(&state_mux);
        enqueue_line("ACK,MAARS,FLAG,ALERT");
        return;
    }
    if (strcmp(line, "MAARS,STATUS") == 0) {
        bool enabled; uint16_t victim;
        portENTER_CRITICAL(&state_mux);
        enabled = stage7b_shadow_enabled;
        victim = stage7b_requested_victim;
        portEXIT_CRITICAL(&state_mux);
        char out[160];
        snprintf(out, sizeof(out),
                 "MAARSSTAT,SHADOW,%u,%u,%u,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%d",
                 (unsigned)enabled, (unsigned)victim,
                 (unsigned)stage7b_current, superframe_number,
                 stage7b_selection_count, stage7b_blocked_count,
                 stage7b_last_result);
        enqueue_line(out);
        return;
    }
    if (strcmp(line, "MAARS,LIST") == 0) {
        char out[160];
        for (uint16_t j = 0; j < stage7b_catalog.schedule_count; ++j) {
            snprintf(out, sizeof(out), "MAARSLABEL,%u,%s",
                     (unsigned)j, stage7b_schedule_names[j]);
            enqueue_line(out);
        }
        return;
    }
    if (strcmp(line, "TS,ON") == 0 || strcmp(line, "TS,OFF") == 0) {
        if (stage7c_requested || stage7c_active) { enqueue_line("ERR,MAARS,DEMO_OWNS_POLICY"); return; }
        ts_requested_random = strcmp(line, "TS,ON") == 0;
        enqueue_line(ts_requested_random ? "ACK,TS,ON" : "ACK,TS,OFF");
        return;
    }
    if (strcmp(line, "TS,RESETSTATS") == 0) {
        ts_decisions=0;
	ts_inversions=0;
	ts_overruns=0;
        ts_release_overlaps=0;
        ts_deadline_miss=0;
        ts_clear_diagnostics();
        trace_drops=0;
        enqueue_line("ACK,TS,RESETSTATS");
        return;
    }
    if (strcmp(line, "TS,DETAIL") == 0) {
        char out[172];
        snprintf(out,sizeof(out),
                 "TSDIAG,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
                 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
                 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32,
                 ts_bad_acks,ts_elapsed_overruns,ts_budget_underflows,
                 ts_max_elapsed_excess_us,
                 ts_task_elapsed_overruns[0],ts_task_elapsed_overruns[1],
                 ts_task_elapsed_overruns[2],ts_task_elapsed_overruns[3],
                 ts_task_elapsed_overruns[4],
                 ts_task_budget_underflows[0],ts_task_budget_underflows[1],
                 ts_task_budget_underflows[2],ts_task_budget_underflows[3],
                 ts_task_budget_underflows[4]);
        enqueue_line(out);
        return;
    }
    if (strcmp(line, "TS,TRACE") == 0) {
        char out[120];
        snprintf(out,sizeof(out),"TSTRACE,%" PRIu32 ",%" PRIu32
                 ",%" PRIu32,trace_drops,lost_lines,lost_events);
        enqueue_line(out);
        return;
    }
    if (strcmp(line, "TS,STATUS") == 0) {
        char out[160];
        snprintf(out,sizeof(out), "TSSTAT,%u,%" PRIu32 ",%" PRIu32
                 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32,
                 (unsigned)ts_requested_random, ts_decisions,
                 ts_inversions, ts_overruns, ts_release_overlaps,
                 ts_deadline_miss);
        enqueue_line(out);
        return;
    }
    if (strcmp(line, "RESET") == 0) {
        if (stage7c_active) ts_requested_random = stage7c_prior_ts_random;
        stage7d_auto = false;
        stage7d_seen = stage7d_events;
        stage7c_requested = false;
        stage7c_active = false;
        stage7c_victim = 0;
        stage7c_current = MAARS_NONE;
        stage7c_commits = 0;
        stage7c_blocks = 0;
        portENTER_CRITICAL(&state_mux);
        stage7b_shadow_enabled = false;
        stage7b_requested_victim = 0;
        portEXIT_CRITICAL(&state_mux);
        stage7b_current = MAARS_NONE;
        stage7b_selection_count = 0;
        stage7b_blocked_count = 0;
        stage7b_last_result = 0;
        xQueueReset(sensor_queue);
        portENTER_CRITICAL(&actuator_mux);
        pending_cmd.valid = false;
        s9f1_window_open=false;
        s9f1_requested=false; s9f1_active=false;
        attack_enabled = false;
        attacker_target_period_us = TARGET_PERIOD_US;
        overwrite_count = 0;
        inference_reset_requested = true;
        ts_decisions=0;
        ts_inversions=0;
        ts_overruns=0;
        ts_release_overlaps=0;
        ts_deadline_miss=0;
        ts_clear_diagnostics();
        trace_drops=0;
        portEXIT_CRITICAL(&actuator_mux);
        portENTER_CRITICAL(&state_mux);
        reset_requested = true;
        portEXIT_CRITICAL(&state_mux);
        enqueue_line("ACK,RESET");
        return;
    }
    if (strcmp(line, "ATTACK,ON") == 0 ||
        strcmp(line, "ATTACK,OFF") == 0) {
        bool enable = strcmp(line, "ATTACK,ON") == 0;
        portENTER_CRITICAL(&actuator_mux);
        attack_enabled = enable;
        portEXIT_CRITICAL(&actuator_mux);
        enqueue_line(enable ? "ACK,ATTACK,ON" : "ACK,ATTACK,OFF");
        return;
    }
    
    if (strcmp(line, "ATKPRIOR,20") == 0 ||
        strcmp(line, "ATKPRIOR,25") == 0) {
        uint32_t prior = strcmp(line, "ATKPRIOR,25") == 0 ? 25000U : 20000U;
        portENTER_CRITICAL(&actuator_mux);
        bool armed = attack_enabled;
        if (!armed) {
            attacker_target_period_us = prior;
            inference_reset_requested = true;
        }
        portEXIT_CRITICAL(&actuator_mux);
        if (armed) enqueue_line("ERR,ATKPRIOR,ATTACK_ARMED");
        else enqueue_line(prior == 25000U ?
                          "ACK,ATKPRIOR,25" : "ACK,ATKPRIOR,20");
        return;
    }
    if (strcmp(line, "ATKPRIOR,STATUS") == 0) {
        uint32_t prior;
        portENTER_CRITICAL(&actuator_mux);
        prior = attacker_target_period_us;
        portEXIT_CRITICAL(&actuator_mux);
        enqueue_line(prior == 25000U ?
                     "ATKPRIORSTAT,25" : "ATKPRIORSTAT,20");
        return;
    }
    if (strcmp(line, "RATE,20") == 0 || strcmp(line, "RATE,25") == 0 ||
        strcmp(line, "RATE,ALT") == 0) {
        if (stage7c_requested || stage7c_active) { enqueue_line("ERR,MAARS,DEMO_OWNS_RATE"); return; }
        rate_mode_t choice = strcmp(line, "RATE,20") == 0 ? RATE_FIXED_20 :
                             strcmp(line, "RATE,25") == 0 ? RATE_FIXED_25 : RATE_ALTERNATE;
        portENTER_CRITICAL(&state_mux);
        requested_rate_mode = choice;
        portEXIT_CRITICAL(&state_mux);
        
        enqueue_line(choice == RATE_FIXED_20 ? "ACK,RATE,20" :
                     choice == RATE_FIXED_25 ? "ACK,RATE,25" : "ACK,RATE,ALT");
        return;
    }
    if (strcmp(line, "RATE,STATUS") == 0) {
        rate_mode_t choice;
        portENTER_CRITICAL(&state_mux);
        choice = requested_rate_mode;
        portEXIT_CRITICAL(&state_mux);
        char reply[144];
        snprintf(reply, sizeof(reply), "RATESTAT,%u,%" PRIu32 ",%" PRIu32
                 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32,
                 (unsigned)choice, active_rate_period_ms,
                 superframe_number, rate_switch_count,
                 workers[0].dropped, workers[3].dropped);
        enqueue_line(reply);
        return;
    }
    if (strncmp(line, "R,", 2) == 0) {
        float x;
        char tail;
        if (sscanf(line + 2, "%f%c", &x, &tail) == 1 &&
            isfinite(x) && x >= -100.0f && x <= 100.0f) {
            portENTER_CRITICAL(&state_mux);
            setpoint = x;
            portEXIT_CRITICAL(&state_mux);
            char reply[48];
            snprintf(reply, sizeof(reply), "ACK,R,%.3f", x);
            enqueue_line(reply);
        } else {
            rx_bad++;
            enqueue_line("ERR,RANGE_OR_FORMAT");
        }
        return;
    }
    if (strcmp(line, "PROTO,STATUS") == 0) {
        char out[240];
        snprintf(out, sizeof(out),
            "PROTOSTAT,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
            ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
            ",%" PRIu32 ",%" PRIu32 ",%u",
            rx_samples, rx_bad, proto_last_rx_seq, proto_last_seen_seq,
            proto_last_valid_seq, proto_last_tx_seq, cmd_sent,
            proto_rejected_sensor_count, trace_drops, lost_lines,
            (unsigned)uxQueueMessagesWaiting(sensor_queue));
        enqueue_line(out);
        return;
    }
    if (strncmp(line, "S,", 2) == 0) {
        uint32_t seq;
        float omega;
        char tail;
        if (sscanf(line + 2, "%" SCNu32 ",%f%c", &seq, &omega, &tail) == 2 &&
            isfinite(omega) && fabsf(omega) <= 1000.0f) {
            sensor_t s = {seq, omega, esp_timer_get_time()};
            chi8_observe_sensor(seq,omega);
            xQueueOverwrite(sensor_queue, &s);
            proto_last_rx_seq = seq;
            rx_samples++;
        } else {
            rx_bad++;
            enqueue_line("ERR,SAMPLE_FORMAT");
        }
        return;
    }
    rx_bad++;
    enqueue_line("ERR,UNKNOWN_COMMAND");
}


static void serial_rx_task(void *arg)
{
    (void)arg;
    char line[88];
    size_t used = 0;
    uint8_t input[64];
    for (;;) {
        ssize_t n = read(STDIN_FILENO, input, sizeof(input));
        if (n > 0) {
            for (ssize_t j = 0; j < n; ++j) {
                char ch = (char)input[j];
                if (ch == '\n' || ch == '\r') {
                    if (used > 0) {
                        line[used] = '\0';
                        parse_input(line);
                        used = 0;
                    }
                } else if ((unsigned char)ch >= 32 &&
                           (unsigned char)ch < 127) {
                    if (used < sizeof(line)-1) line[used++] = ch;
                    else { used = 0; rx_bad++; }
                }
            }
        }
        vTaskDelay(1);
    }
}

void app_main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    sensor_queue = xQueueCreate(1, sizeof(sensor_t));
    event_queue = xQueueCreate(256, sizeof(timing_t));
    output_queue = xQueueCreate(128, sizeof(line_t));
    ts_ack_queue = xQueueCreate(2, sizeof(ts_ack_t));
    trace_queue = xQueueCreate(128, sizeof(trace_record_t));
    configASSERT(sensor_queue && event_queue && output_queue && ts_ack_queue && trace_queue);

    configASSERT(xTaskCreatePinnedToCore(writer_task, "SERIAL_WRITER", 4096,
                                         NULL, 9, NULL, 1) == pdPASS);
    configASSERT(xTaskCreatePinnedToCore(serial_rx_task, "SERIAL_RX", 4096,
                                         NULL, 10, NULL, 1) == pdPASS);
    configASSERT(xTaskCreatePinnedToCore(event_logger_task, "EVENT_LOG", 4096,
                                         NULL, 4, NULL, 1) == pdPASS);
    configASSERT(xTaskCreatePinnedToCore(trace_format_task, "TRACE_FMT", 6144,
                                         NULL, 7, NULL, 1) == pdPASS);
    for (int i = 0; i < NUM_WORKERS; ++i) {
        worker_t *w = &workers[i];
        w->releases = xQueueCreate(8, sizeof(release_t));
        configASSERT(w->releases);
        TaskFunction_t fn = (i == 0) ? control_task :
                            (i == 3) ? tx_task : dummy_task;
        configASSERT(xTaskCreatePinnedToCore(fn, w->name, 4096, w,
                                             8, &w->task, 0) == pdPASS);
    }

    configASSERT(xTaskCreatePinnedToCore(ts_dispatcher_task, "TASKSHUFFLER",
                                         6144, NULL, 16,
                                         &ts_dispatcher_handle, 0) == pdPASS);
    esp_timer_create_args_t timer_args = {
        .callback = on_grid_tick,
        .arg = NULL,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "maars_grid_stage5d",
   };
    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &grid_timer));
    enqueue_line("READY,MAARS_STAGE5D,PERIOD_MS=20,TX_OFFSET_MS=8");
    epoch_us = esp_timer_get_time();
    ESP_ERROR_CHECK(esp_timer_start_periodic(grid_timer, GRID_US));
}

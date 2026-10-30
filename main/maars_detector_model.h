/* Fixed residual-detector coefficients from a baseline calibration.
 * Model state [armature current, shaft angular velocity]. */
#ifndef MAARS_DETECTOR_MODEL_H
#define MAARS_DETECTOR_MODEL_H
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#define CHI8_WINDOW 10
#define CHI8_A00 (0.12068804594421013)
#define CHI8_A01 (-0.042281095185138534)
#define CHI8_A10 (0.42281095185138512)
#define CHI8_A11 (0.96208184012846709)
#define CHI8_B0 (0.42561845604747017)
#define CHI8_B1 (0.28075041960849551)
#define CHI8_K0 (-0.007622457691163975)
#define CHI8_K1 (0.22803586033961382)
#define CHI8_SIGMA2 (0.25)
#define CHI8_THRESHOLD (1.9184644345777788)

typedef struct {
    double i, w;                /* posterior observer state */
    double z_history[CHI8_WINDOW];
    double z_sum;
    uint32_t samples, alarms, resets, missing_voltage;
    uint32_t last_seq;
    unsigned int used, z_head, quiet;
    bool initialized, alarm;
    double last_g, last_z, last_prediction, last_residual;
} chi8_model_t;


static inline bool chi8_model_step(chi8_model_t *m,uint32_t seq,double omega,
                                    bool has_u_prev,double u_prev)
{
    bool cont = m->initialized && seq==m->last_seq+1U && has_u_prev;
    if (!cont) {
        if (m->initialized) {
            ++m->resets;
            if (!has_u_prev && seq==m->last_seq+1U) ++m->missing_voltage;
        }
        m->i=0.0;m->w=omega;m->used=0;m->z_head=0;m->z_sum=0.0;
        m->alarm=false;m->quiet=0;
        m->initialized=true;
    } else {
        const double ni=CHI8_A00*m->i+CHI8_A01*m->w+CHI8_B0*u_prev;
        const double nw=CHI8_A10*m->i+CHI8_A11*m->w+CHI8_B1*u_prev;
        m->i=ni;m->w=nw;
    }
    const double predicted=m->w;
    const double residual=omega-predicted;
    m->i+=CHI8_K0*residual;
    m->w+=CHI8_K1*residual;
    const double z=residual*residual/CHI8_SIGMA2;
    if (m->used==CHI8_WINDOW) m->z_sum-=m->z_history[m->z_head];
    else ++m->used;
    m->z_history[m->z_head]=z;
    m->z_sum+=z;
    m->z_head=(m->z_head+1U)%CHI8_WINDOW;
    m->last_g=m->used==CHI8_WINDOW?m->z_sum/(double)CHI8_WINDOW:-1.0;
    m->last_z=z;
    m->last_prediction=predicted;
    m->last_residual=residual;
    m->alarm=m->used==CHI8_WINDOW && m->last_g>CHI8_THRESHOLD;
    if(m->alarm){++m->alarms;m->quiet=0;}
    else if(m->used==CHI8_WINDOW) ++m->quiet;
    m->last_seq=seq;
    ++m->samples;
    return cont;
}
#endif

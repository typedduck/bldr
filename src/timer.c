/**
 * @file timer.c
 * @brief Timer with timeout and gradually increasing sleep durations
 *
 */

#include "../include/bldr.h"

/* Everything above and including line 9 is deleted in the stb-library */

/*
 * Timer function implementations
 */

constexpr long _bldr_timer_min_sleep = 1000;  // 1ms minimum
constexpr long _bldr_timer_max_sleep = 50000; // 50ms maximum

int bldr_timer_init(bldr_timer_t *timer, long timeout_ms) {
    memset(timer, 0, sizeof(*timer));
    timer->timeout = (double)timeout_ms / 1000.0;
    return BLDR_OK;
}

int bldr_timer_init_now(bldr_timer_t *timer, long timeout_ms) {
    bldr_timer_init(timer, timeout_ms);
    bldr_timer_start(timer);
    return BLDR_OK;
}

int bldr_timer_sleep(bldr_timer_t *timer) {
    double elapsed_time = bldr_time_now() - timer->start;

    if (elapsed_time >= timer->timeout) {
        return BLDR_ERR_TIMEOUT;
    }
    // For the last second, use shorter sleep intervals for
    // responsiveness
    if (elapsed_time >= timer->timeout - 1) {
        timer->sleep = _bldr_timer_min_sleep;
    }
    // Sleep with adaptive interval (exponential backoff with cap)
    usleep(timer->sleep);
    // Gradually increase sleep time to reduce CPU usage with 1.5x
    // multiplier
    timer->sleep = MIN((timer->sleep * 3) / 2, _bldr_timer_max_sleep);

    return BLDR_OK;
}

void bldr_timer_start(bldr_timer_t *timer) {
    timer->start = bldr_time_now();
    timer->sleep = _bldr_timer_min_sleep;
}

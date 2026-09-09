/**
 * @file    main.h
 * @brief   Host stand-in for CubeIDE main.h (HAL_GetTick for se_time)
 */
#ifndef __MAIN_H
#define __MAIN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t HAL_GetTick(void);

#ifdef __cplusplus
}
#endif

#endif /* __MAIN_H */

#ifndef LOW_LEVEL_OTP_H
#define LOW_LEVEL_OTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define OTP_NVCNT_NUMBER 60                             /* OTP 60 - 75 : Non-volatile counters */
#define OTP_DEBUG_AUTH_PASSWORD_HASH_NUMBER 292         /* OTP 292 - 299 : Debug authentication password hash */

#define ECDSA_256_PRIV_KEY_LENGTH (32U)
#define SHA256_LENGTH             (32U)

typedef enum {
    CONFIG_STAGE,
    CHECK_STAGE,
} FlowStage_t;

/* Get keys */
int OTP_InitKeys(void);

/* Lock config or check lock status of OTP */
int OTP_Lock_Cfg(FlowStage_t stage);

/* Increase the protection level */
int Increase_HDPL(FlowStage_t stage);

#ifdef __cplusplus
}
#endif

#endif /* LOW_LEVEL_OTP_H */
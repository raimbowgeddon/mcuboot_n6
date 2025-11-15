#include "low_level_otp.h"
#include <stm32n6xx_hal.h>
#include <stm32n6xx_hal_bsec.h>
#include <zephyr/kernel.h>

/* Private defines -----------------------------------------------------------*/
#define AUTH_PUB_KEY_HASH_OTP_NUMBER          268       /* OTP 276 - 283 : Non Secure authentication public key hash */
#define ENC_PRIV_KEY_OTP_NUMBER               284       /* OTP 284 - 291 : Encryption private key */

/* Global variables ----------------------------------------------------------*/
uint8_t Authentication_Public_Key_HASH[SHA256_LENGTH];
uint8_t Encryption_Private_Key[ECDSA_256_PRIV_KEY_LENGTH];

/* Reverse memecopy */
static void rev_memcpy(uint32_t *dest, const uint32_t *src, size_t n);

/* Functions Definition ------------------------------------------------------*/

/**
  * @brief Retrieve OEMuROT keys from OTP words.
  *
  * This function reads OTP fuse values :
  * - Secure authentication public key hash
  * - Non Secure authentication public key hash
  * - Encryption private key
  */
int OTP_InitKeys(void)
{
  BSEC_HandleTypeDef sBsecHandler = {0};
  uint32_t otp_value[SHA256_LENGTH / 4] = {0};
  uint32_t i = 0;

  sBsecHandler.Instance = BSEC;

  /* Read non-secure authentication public key hash located in OTP 276-283 */
  for (i = 0; i < (SHA256_LENGTH / 4); i++)
  {
    if (HAL_BSEC_OTP_Read(&sBsecHandler, AUTH_PUB_KEY_HASH_OTP_NUMBER + i, &(otp_value[i])) != HAL_OK)
    {
      return -EINVAL;
    }
  }
  rev_memcpy((uint32_t*)Authentication_Public_Key_HASH, otp_value, SHA256_LENGTH / 4);


  /* Read encryption private key located in OTP 284-291 */
  for (i = 0; i < (ECDSA_256_PRIV_KEY_LENGTH / 4); i++)
  {
    if (HAL_BSEC_OTP_Read(&sBsecHandler, ENC_PRIV_KEY_OTP_NUMBER + i, &(otp_value[i])) != HAL_OK)
    {
      return -EINVAL;
    }
  }
  rev_memcpy((uint32_t*)Encryption_Private_Key, otp_value, SHA256_LENGTH / 4);

  return 0;
}

/**
  * @brief Lock/Verify OEMuROT OTP slots.
  *
  * This function make OEMuROT OTP fuses unreadable :
  * - Secure authentication public key hash
  * - Non Secure authentication public key hash
  * - Encryption private key
  * - Debug authentication password hash
  */
int OTP_Lock(FlowStage_t stage)
{
  BSEC_HandleTypeDef sBsecHandler = {0};
  uint32_t State = 0U;
  uint32_t i = 0, j = 0;

  sBsecHandler.Instance = BSEC;

  /* Configuration stage */
  if (stage == CONFIG_STAGE)
  {
    /* Lock NVCNT OTP */
    for (j = 0; j < 4; j++)
    {
      for (i = 0; i < 4; i++)
      {
        if (HAL_BSEC_OTP_Lock(&sBsecHandler, OTP_NVCNT_NUMBER + 4 * j + i, HAL_BSEC_FUSE_RELOAD_LOCKED) != HAL_OK)
        {
          return -EINVAL;
        }
      }
    }

    /* Lock DA password OTP */
    for (i = 0; i < 4; i++)
    {
      if (HAL_BSEC_OTP_Lock(&sBsecHandler, OTP_DEBUG_AUTH_PASSWORD_HASH_NUMBER + i, HAL_BSEC_FUSE_RELOAD_LOCKED) != HAL_OK)
      {
        return -EINVAL;
      }
    }

    /* Lock non-secure authentication public key OTP */
    for (i = 0; i < (SHA256_LENGTH / 4); i++)
    {
      if (HAL_BSEC_OTP_Lock(&sBsecHandler, AUTH_PUB_KEY_HASH_OTP_NUMBER + i, HAL_BSEC_FUSE_RELOAD_LOCKED) != HAL_OK)
      {
        return -EINVAL;
      }
    }

    /* Lock encryption private key OTP */
    for (i = 0; i < (ECDSA_256_PRIV_KEY_LENGTH / 4); i++)
    {
      if (HAL_BSEC_OTP_Lock(&sBsecHandler, ENC_PRIV_KEY_OTP_NUMBER + i, HAL_BSEC_FUSE_RELOAD_LOCKED) != HAL_OK)
      {
        return -EINVAL;
      }
    }
  }
  /* Verification stage */
  else
  {
    /* Verify OTP : NVCNT */
    for (j = 0; j < 4; j++)
    {
      for (i = 0; i < 4; i++)
      {
        if (HAL_BSEC_OTP_GetState(&sBsecHandler, OTP_NVCNT_NUMBER + 4 * j + i, &State) != HAL_OK)
        {
          return -EINVAL;
        }
        else
        {
          if ((State & HAL_BSEC_FUSE_RELOAD_LOCKED) != HAL_BSEC_FUSE_RELOAD_LOCKED)
          {
            return -EINVAL;
          }
        }
      }
    }

    /* Verify OTP : DA password */
    for (i = 0; i < 4; i++)
    {
      if (HAL_BSEC_OTP_GetState(&sBsecHandler, OTP_DEBUG_AUTH_PASSWORD_HASH_NUMBER + i, &State) != HAL_OK)
      {
        return -EINVAL;
      }
    }

    /* Verify OTP : non-secure authentication public key */
    for (i = 0; i < (SHA256_LENGTH / 4); i++)
    {
      if (HAL_BSEC_OTP_GetState(&sBsecHandler, AUTH_PUB_KEY_HASH_OTP_NUMBER + i, &State) != HAL_OK)
      {
        return -EINVAL;
      }
      else
      {
        if ((State & HAL_BSEC_FUSE_RELOAD_LOCKED) != HAL_BSEC_FUSE_RELOAD_LOCKED)
        {
          return -EINVAL;
        }
      }
    }

    /* Verify OTP : encryption private key */
    for (i = 0; i < (ECDSA_256_PRIV_KEY_LENGTH / 4); i++)
    {
      if (HAL_BSEC_OTP_GetState(&sBsecHandler, ENC_PRIV_KEY_OTP_NUMBER + i, &State) != HAL_OK)
      {
        return -EINVAL;
      }
      else
      {
        if ((State & HAL_BSEC_FUSE_RELOAD_LOCKED) != HAL_BSEC_FUSE_RELOAD_LOCKED)
        {
          return -EINVAL;
        }
      }
    }
  }

  return 0;
}

/**
  * @brief Increase Hide Protection Level
  *
  * On configuration stage, this function increase the hide protection level
  * to 2, assuming that the current level is 1, and verifies that it is correctly set to 2
  * during the verification stage.
  */
int Increase_HDPL(FlowStage_t stage)
{
  BSEC_HandleTypeDef sBsecHandler = {0};
  uint32_t HDPL = HAL_BSEC_HDPL_VALUE_3;
  sBsecHandler.Instance = BSEC;

  /* Configuration stage */
  if (stage == CONFIG_STAGE)
  {
    /* Increase HDPL to 2 */
    if (HAL_BSEC_IncrementHDPLValue(&sBsecHandler) != HAL_OK)
    {
      return -EINVAL;
    }
  }
  /* Verification stage */
  else
  {
    /* Get HDPL level */
    if (HAL_BSEC_GetHDPLValue(&sBsecHandler, &HDPL) != HAL_OK)
    {
      return -EINVAL;
    }

    /* Verify that HDPL is set to 2 */
    if (HDPL != HAL_BSEC_HDPL_VALUE_2)
    {
      return -EINVAL;
    }
  }

  return 0;
}

/**
  * @brief Reverse Endian Memory Copy
  *
  * This function copies n 32-bit words from the source array to the destination array,
  * reversing the endianness of each word during the copy process.
  *
  * @param dest Pointer to the destination array where the data will be copied.
  * @param src Pointer to the source array from which the data will be copied.
  * @param n Number of 32-bit words to copy.
  */
static void rev_memcpy(uint32_t *dest, const uint32_t *src, size_t n)
{
  uint32_t i = 0;

  /* Copy n bytes from source to destination by reversing endianness*/
  for (i = 0; i < n; i++)
  {
    dest[i] = __REV(src[i]);
  }
}

/*
 *  ccblowfish.h
 *  corecrypto
 *
 *  Created by Michael Brouwer on 12/10/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCBLOWFISH_H_
#define _CORECRYPTO_CCBLOWFISH_H_

#include <corecrypto/cc_config.h>
#include <corecrypto/ccmode.h>

#define CCBLOWFISH_BLOCK_SIZE 16
#define CCBLOWFISH_MIN_KEY_SIZE 4
#define CCBLOWFISH_MAX_KEY_SIZE 56

extern const struct ccmode_ecb ccblowfish_ltc_ecb_decrypt_mode;
extern const struct ccmode_ecb ccblowfish_ltc_ecb_encrypt_mode;

/* Implementation Selectors: */
const struct ccmode_ecb *ccblowfish_ecb_encrypt_mode(void);
const struct ccmode_cbc *ccblowfish_cbc_encrypt_mode(void);
const struct ccmode_cfb *ccblowfish_cfb_encrypt_mode(void);
const struct ccmode_cfb8 *ccblowfish_cfb8_encrypt_mode(void);

const struct ccmode_ecb *ccblowfish_ecb_decrypt_mode(void);
const struct ccmode_cbc *ccblowfish_cbc_decrypt_mode(void);
const struct ccmode_cfb *ccblowfish_cfb_decrypt_mode(void);
const struct ccmode_cfb8 *ccblowfish_cfb8_decrypt_mode(void);

const struct ccmode_ctr *ccblowfish_ctr_crypt_mode(void);
const struct ccmode_ofb *ccblowfish_ofb_crypt_mode(void);

#endif /* _CORECRYPTO_CCBLOWFISH_H_ */

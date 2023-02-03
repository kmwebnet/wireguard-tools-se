#ifndef SE_HELPER_H
#define SE_HELPER_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fsl_sss_ftr.h"

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <nxLog_App.h>
#include <se05x_APDU.h>
#include "fsl_sss_api.h"
#include "ex_sss_objid.h"

#define OBJID_device_key (EX_SSS_OBJID_CUST_START + 0x10000001u)

int gen_se_key(uint32_t keyID);

int get_se_key(uint8_t * key, uint32_t keyID);

int get_se_rand(uint8_t * random, size_t rand_len);

#endif
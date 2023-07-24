// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2023 kmwebnet <kmwebnet@gmail.com>. All Rights Reserved.
 */

#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>

#include "se-helper.h"

#define SHM_NAME "/se-helper"

#define I2C_DEFAULT_PORT "/dev/i2c-1"

#define PEXIT(msg) do{ perror(msg); exit(EXIT_FAILURE); }while(0)

#define EX_SSS_AUTH_SE05X_NONE_AUTH_ID 0x00000000
#define EX_LOCAL_OBJ_AUTH_ID EX_SSS_AUTH_SE05X_NONE_AUTH_ID


int gen_se_key(uint32_t keyID)
{

    //prepare LOCK

    pthread_mutex_t *mp;

    int fd = shm_open(SHM_NAME, O_RDWR, 0600);
    if(fd<0){
        fd = shm_open(SHM_NAME, O_CREAT|O_EXCL|O_RDWR, 0600);
        if(fd<0) PEXIT("shm_open O_CREAT");

        ftruncate(fd, sizeof(pthread_mutex_t));
        mp = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

        pthread_mutexattr_t mattr;
        pthread_mutexattr_init(&mattr); 
        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED); 
        pthread_mutex_init(mp, &mattr); 
    }else{
        mp = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    }

    //do LOCK
    pthread_mutex_lock(mp);

	sss_status_t status = kStatus_SSS_Success;

    const sss_policy_u ecc_key_pol = {.type = KPolicy_Asym_Key,
        .auth_obj_id                        = 0,
        .policy                             = {.asymmkey = {
                       .can_Verify        = 1,
                       .can_Encrypt       = 1,
                       .can_Gen           = 1,
                       .can_Import_Export = 1,
                       .can_KA            = 1,
                       .can_Attest        = 1,
                   }}};
    const sss_policy_u common      = {.type = KPolicy_Common,
        .auth_obj_id                   = 0,
        .policy                        = {.common = {
                       .can_Delete = 1,
                       .can_Read   = 1,
                       .can_Write  = 0,
                   }}};

    sss_policy_t policy_for_ec_key = {.nPolicies = 2, .policies = {&ecc_key_pol, &common}};


    static ex_sss_boot_ctx_t pCtx;
    status = ex_sss_boot_open(&pCtx, I2C_DEFAULT_PORT);
    if (status != kStatus_SSS_Success) {
        printf("ex_sss_boot_open failed");
        goto failure;
    };    

    status = ex_sss_key_store_and_object_init(&pCtx);
	if (status != kStatus_SSS_Success)
	{
 
        printf("ex_sss_key_store_and_object_init failed");
        goto failure;
    }    


    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx.session;

    smStatus_t sw_status;
    SE05x_Result_t result = kSE05x_Result_NA;

    sw_status = Se05x_API_CheckObjectExists(
        &pSession->s_ctx, keyID, &result);
    if (SM_OK != sw_status) {
        printf("Failed Se05x_API_CheckObjectExists");
        goto failure;
    }
    if (result == kSE05x_Result_SUCCESS) {
        sw_status = Se05x_API_DeleteSecureObject(&pSession->s_ctx, keyID);
        if (SM_OK != sw_status) {
            printf("Failed Se05x_API_DeleteSecureObject");
            goto failure;
        }
    }



    sss_object_t keypair;

	status = sss_key_store_context_init(&pCtx.ks, &pCtx.session);
	if (status != kStatus_SSS_Success)
	{
        ex_sss_session_close(&pCtx);
        printf("sss_key_store_context_init failed");
        goto failure;
    }

    status = sss_key_store_allocate(&pCtx.ks, keyID);
    if (status != kStatus_SSS_Success)
	{
        sss_key_store_context_free(&pCtx.ks);
        ex_sss_session_close(&pCtx);
        printf("sss_key_store_allocate failed");
        goto failure;
    }

	status = sss_key_object_init(&keypair, &pCtx.ks);
	if (status != kStatus_SSS_Success)
	{
        sss_key_store_context_free(&pCtx.ks);
        ex_sss_session_close(&pCtx);
        printf("sss_key_object_init failed");
        goto failure;
    }

	status = sss_key_object_allocate_handle(
		&keypair,
		keyID,
		kSSS_KeyPart_Pair,
		kSSS_CipherType_EC_MONTGOMERY,
		256 ,
		kKeyObject_Mode_Persistent
	);
	if (status != kStatus_SSS_Success)
	{
        sss_key_object_free(&keypair);
        sss_key_store_context_free(&pCtx.ks);
        ex_sss_session_close(&pCtx);
        printf("sss_key_object_allocate_handle failed");
        goto failure;
    }

    status = sss_key_store_generate_key(&pCtx.ks, &keypair, 256, &policy_for_ec_key);
	if (status != kStatus_SSS_Success)
	{
        sss_key_object_free(&keypair);
        sss_key_store_context_free(&pCtx.ks);
        ex_sss_session_close(&pCtx);
        printf("sss_key_store_generate_key failed");
        goto failure;
    }

    status = sss_key_store_save(&pCtx.ks);
	if (status != kStatus_SSS_Success)
	{
        sss_key_object_free(&keypair);
        sss_key_store_context_free(&pCtx.ks);
        ex_sss_session_close(&pCtx);
        printf("sss_key_store_save failed");
        goto failure;
    }	
    sss_key_object_free(&keypair);
    sss_key_store_context_free(&pCtx.ks);
    ex_sss_session_close(&pCtx);

// cleanup
    pthread_mutex_unlock(mp);
    pthread_mutex_destroy(mp);
    munmap(mp, sizeof(pthread_mutex_t));
    shm_unlink(SHM_NAME);    

	return EXIT_SUCCESS;

failure:
    pthread_mutex_unlock(mp);
    pthread_mutex_destroy(mp);
    munmap(mp, sizeof(pthread_mutex_t));
    shm_unlink(SHM_NAME);

    return EXIT_FAILURE;
};

int get_se_key(uint8_t * key, uint32_t keyID)
{

    //prepare LOCK

    pthread_mutex_t *mp;

    int fd = shm_open(SHM_NAME, O_RDWR, 0600);
    if(fd<0){
        fd = shm_open(SHM_NAME, O_CREAT|O_EXCL|O_RDWR, 0600);
        if(fd<0) PEXIT("shm_open O_CREAT");

        ftruncate(fd, sizeof(pthread_mutex_t));
        mp = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

        pthread_mutexattr_t mattr;
        pthread_mutexattr_init(&mattr); 
        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED); 
        pthread_mutex_init(mp, &mattr); 
    }else{
        mp = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    }

    //do LOCK
    pthread_mutex_lock(mp);

	sss_status_t status = kStatus_SSS_Success;

    static ex_sss_boot_ctx_t pCtx;
    status = ex_sss_boot_open(&pCtx, I2C_DEFAULT_PORT);
    if (status != kStatus_SSS_Success) {
        printf("ex_sss_boot_open failed");
        goto failure;
    };    

    status = ex_sss_key_store_and_object_init(&pCtx);
	if (status != kStatus_SSS_Success)
	{
 
        printf("ex_sss_key_store_and_object_init failed");
        goto failure;
    }    

    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&pCtx.session;

    smStatus_t sw_status;
    SE05x_Result_t result = kSE05x_Result_NA;

    sw_status = Se05x_API_CheckObjectExists(
        &pSession->s_ctx, keyID, &result);
    if (SM_OK != sw_status) {
        printf("Failed Se05x_API_CheckObjectExists");
        goto failure;
    }
    if (result != kSE05x_Result_SUCCESS) {
        printf("private key does not exist. generate key first.\n");
        goto failure;
    }

    sss_object_t keypair;

	status = sss_key_store_context_init(&pCtx.ks, &pCtx.session);
	if (status != kStatus_SSS_Success)
	{
        ex_sss_session_close(&pCtx);
        printf("sss_key_store_context_init failed");
        goto failure;
    }

    status = sss_key_store_allocate(&pCtx.ks, keyID);
    if (status != kStatus_SSS_Success)
	{
        sss_key_store_context_free(&pCtx.ks);
        ex_sss_session_close(&pCtx);
        printf("sss_key_store_allocate failed");
        goto failure;
    }

	status = sss_key_object_init(&keypair, &pCtx.ks);
	if (status != kStatus_SSS_Success)
	{
        sss_key_store_context_free(&pCtx.ks);
        ex_sss_session_close(&pCtx);
        printf("sss_key_object_init failed");
        goto failure;
    }

	status = sss_key_object_get_handle(
		&keypair,
		keyID
	);
	if (status != kStatus_SSS_Success)
	{
        sss_key_object_free(&keypair);
        sss_key_store_context_free(&pCtx.ks);
        ex_sss_session_close(&pCtx);
        printf("sss_key_object_get_handle failed");
        goto failure;
    }

    uint8_t           derbuf[64];
    size_t            dersz = sizeof(derbuf);
    size_t            derszbits = dersz * 8;

    status = sss_key_store_get_key(&pCtx.ks, &keypair, derbuf, &dersz, &derszbits);
	if (status != kStatus_SSS_Success)
	{
        sss_key_object_free(&keypair);
        sss_key_store_context_free(&pCtx.ks);
        ex_sss_session_close(&pCtx);
        printf("sss_key_store_get_key failed:%x",status);
        goto failure;
    }	

    sss_key_object_free(&keypair);
    sss_key_store_context_free(&pCtx.ks);
    ex_sss_session_close(&pCtx);
    memcpy(key, &derbuf[12], 32);
    memset(derbuf, 0, dersz);

// cleanup
    pthread_mutex_unlock(mp);
    pthread_mutex_destroy(mp);
    munmap(mp, sizeof(pthread_mutex_t));
    shm_unlink(SHM_NAME);    

	return EXIT_SUCCESS;

failure:
    pthread_mutex_unlock(mp);
    pthread_mutex_destroy(mp);
    munmap(mp, sizeof(pthread_mutex_t));
    shm_unlink(SHM_NAME);

    return EXIT_FAILURE;

};

int get_se_rand(uint8_t * random, size_t rand_len)
{

    //prepare LOCK

    pthread_mutex_t *mp;

    int fd = shm_open(SHM_NAME, O_RDWR, 0600);
    if(fd<0){
        fd = shm_open(SHM_NAME, O_CREAT|O_EXCL|O_RDWR, 0600);
        if(fd<0) PEXIT("shm_open O_CREAT");

        ftruncate(fd, sizeof(pthread_mutex_t));
        mp = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

        pthread_mutexattr_t mattr;
        pthread_mutexattr_init(&mattr); 
        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED); 
        pthread_mutex_init(mp, &mattr); 
    }else{
        mp = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    }

    //do LOCK
    pthread_mutex_lock(mp);

	sss_status_t status = kStatus_SSS_Success;

    static ex_sss_boot_ctx_t pCtx;
    status = ex_sss_boot_open(&pCtx, I2C_DEFAULT_PORT);
    if (status != kStatus_SSS_Success) {
        printf("ex_sss_boot_open failed");
        goto failure;
    };    

	sss_rng_context_t rng;

	status = sss_rng_context_init(&rng, &pCtx.session);
    if (status != kStatus_SSS_Success)
	{
        ex_sss_session_close(&pCtx);
        printf("sss_rng_context_init failed");
        goto failure;
    }	

	status = sss_rng_get_random(&rng, random, rand_len);
	sss_rng_context_free(&rng);

	if (status != kStatus_SSS_Success)
	{
        ex_sss_session_close(&pCtx);
        goto failure;
    }	
    ex_sss_session_close(&pCtx);

// cleanup
    pthread_mutex_unlock(mp);
    pthread_mutex_destroy(mp);
    munmap(mp, sizeof(pthread_mutex_t));
    shm_unlink(SHM_NAME);    

	return EXIT_SUCCESS;

failure:
    pthread_mutex_unlock(mp);
    pthread_mutex_destroy(mp);
    munmap(mp, sizeof(pthread_mutex_t));
    shm_unlink(SHM_NAME);

    return EXIT_FAILURE;


};
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include "ta_rsa_encrypt.h"

#define RSA_KEY_SIZE 2048
#define RSA_KEY_SIZE_BYTES (RSA_KEY_SIZE / 8)

static TEE_ObjectHandle rsa_keypair = TEE_HANDLE_NULL;

TEE_Result TA_CreateEntryPoint(void) {
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    if (rsa_keypair != TEE_HANDLE_NULL)
        TEE_CloseObject(rsa_keypair);
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param params[4],
                                    void **sess_ctx) {
    (void)param_types; (void)params; (void)sess_ctx;
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    (void)sess_ctx;
}

static TEE_Result generate_rsa_keypair(void) {
    TEE_Result res;

    // 이미 열려있으면 바로 리턴
    if (rsa_keypair != TEE_HANDLE_NULL)
        return TEE_SUCCESS;

    // Persistent Object 열기 시도
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                   "rsa_keypair", strlen("rsa_keypair"),
                                   TEE_DATA_FLAG_ACCESS_READ,
                                   &rsa_keypair);
    if (res == TEE_SUCCESS) {
        IMSG("RSA keypair loaded from secure storage.");
        return TEE_SUCCESS;
    }

    IMSG("Generating new RSA keypair...");
    TEE_ObjectHandle transient_key = TEE_HANDLE_NULL;
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, RSA_KEY_SIZE, &transient_key);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_AllocateTransientObject failed: 0x%x", res);
        return res;
    }

    res = TEE_GenerateKey(transient_key, RSA_KEY_SIZE, NULL, 0);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GenerateKey failed: 0x%x", res);
        TEE_FreeTransientObject(transient_key);
        return res;
    }

    // Secure Storage에 저장
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                     "rsa_keypair", strlen("rsa_keypair"),
                                     TEE_DATA_FLAG_ACCESS_READ |
                                     TEE_DATA_FLAG_ACCESS_WRITE |
                                     TEE_DATA_FLAG_ACCESS_WRITE_META,
                                     transient_key, NULL, 0, &rsa_keypair);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_CreatePersistentObject failed: 0x%x", res);
        TEE_FreeTransientObject(transient_key);
        return res;
    }

    IMSG("RSA keypair generated and stored.");
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4]) {
    (void)sess_ctx;
    TEE_Result res;
    IMSG("TA_InvokeCommandEntryPoint: cmd_id = %u", cmd_id);

    if (cmd_id == CMD_RSA_DECRYPT) {
        IMSG("RSA decryption requested");

        if (param_types != TEE_PARAM_TYPES(
                TEE_PARAM_TYPE_MEMREF_INPUT,
                TEE_PARAM_TYPE_MEMREF_OUTPUT,
                TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE)) {
            EMSG("Invalid param types for decrypt: 0x%x", param_types);
            return TEE_ERROR_BAD_PARAMETERS;
        }

        res = generate_rsa_keypair();
        if (res != TEE_SUCCESS) {
            EMSG("generate_rsa_keypair failed: 0x%x", res);
            return res;
        }

        TEE_OperationHandle op;
        res = TEE_AllocateOperation(&op, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT, RSA_KEY_SIZE);
        if (res != TEE_SUCCESS) {
            EMSG("TEE_AllocateOperation failed: 0x%x", res);
            return res;
        }

        res = TEE_SetOperationKey(op, rsa_keypair);
        if (res != TEE_SUCCESS) {
            EMSG("TEE_SetOperationKey failed: 0x%x", res);
            TEE_FreeOperation(op);
            return res;
        }

        size_t out_len = params[1].memref.size;
        res = TEE_AsymmetricDecrypt(op, NULL, 0,
                                    params[0].memref.buffer, params[0].memref.size,
                                    params[1].memref.buffer, &out_len);
        if (res != TEE_SUCCESS) {
            EMSG("TEE_AsymmetricDecrypt failed: 0x%x", res);
        } else {
            IMSG("Decryption successful. Output size: %zu", out_len);
        }

        params[1].memref.size = out_len;
        TEE_FreeOperation(op);
        return res;
    }

    if (cmd_id != CMD_RSA_ENCRYPT) {
        EMSG("Unsupported command ID: %u", cmd_id);
        return TEE_ERROR_NOT_SUPPORTED;
    }

    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
									   TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE)) {
        EMSG("Invalid param types: 0x%x", param_types);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = generate_rsa_keypair();
    if (res != TEE_SUCCESS) {
        return res;
    }

    TEE_OperationHandle op;
    res = TEE_AllocateOperation(&op, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, RSA_KEY_SIZE);
    if (res != TEE_SUCCESS) {
        return res;
    }

    res = TEE_SetOperationKey(op, rsa_keypair);
    if (res != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        return res;
    }

    size_t out_len = params[1].memref.size;
    res = TEE_AsymmetricEncrypt(op, NULL, 0,
                                params[0].memref.buffer, params[0].memref.size,
                                params[1].memref.buffer, &out_len);


    params[1].memref.size = out_len;
    TEE_FreeOperation(op);
    return res;
}

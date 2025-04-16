#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include "ta_rsa_encrypt.h"

#define MAX_BUF_SIZE 256

int main() {
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Result res;
    TEEC_UUID uuid = TA_RSA_ENCRYPT_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed: 0x%x\n", res);
        return 1;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed: 0x%x (origin: 0x%x)\n", res, err_origin);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    const char *plain = "hello world";
    TEEC_SharedMemory in, out;
    in.size = strlen(plain);
    in.flags = TEEC_MEM_INPUT;
    res = TEEC_AllocateSharedMemory(&ctx, &in);
    if (res != TEEC_SUCCESS) {
        printf("Shared memory allocation (input) failed: 0x%x\n", res);
        goto cleanup;
    }
    memcpy(in.buffer, plain, in.size);

    out.size = MAX_BUF_SIZE;
    out.flags = TEEC_MEM_OUTPUT;
    res = TEEC_AllocateSharedMemory(&ctx, &out);
    if (res != TEEC_SUCCESS) {
        printf("Shared memory allocation (output) failed: 0x%x\n", res);
        TEEC_ReleaseSharedMemory(&in);
        goto cleanup;
    }

    TEEC_Operation op = {0};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
                                     TEEC_MEMREF_WHOLE,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].memref.parent = &in;
    op.params[0].memref.size = in.size;
    op.params[1].memref.parent = &out;
    op.params[1].memref.size = out.size;

    res = TEEC_InvokeCommand(&sess, CMD_RSA_ENCRYPT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand (encrypt) failed: 0x%x (origin: 0x%x)\n", res, err_origin);
    } else {
        printf("Encrypted (%zu bytes):\n", op.params[1].memref.size);
        for (size_t i = 0; i < op.params[1].memref.size; ++i)
            printf("%02X", ((unsigned char*)out.buffer)[i]);
        printf("\n");

        // 파일로 저장
        FILE *f = fopen("cipher.bin", "wb");
        if (!f) {
            perror("fopen cipher.bin failed");
        } else {
            fwrite(out.buffer, 1, op.params[1].memref.size, f);
            fclose(f);
            printf("Encrypted output written to cipher.bin\n");
        }
    }

    TEEC_ReleaseSharedMemory(&in);
    TEEC_ReleaseSharedMemory(&out);

cleanup:
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}

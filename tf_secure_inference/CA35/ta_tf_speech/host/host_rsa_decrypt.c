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

    // 샘플 암호문 입력 (256바이트). 예시로 하드코딩하거나 파일로부터 읽을 수 있음.
    unsigned char ciphertext[MAX_BUF_SIZE] = {0};
    size_t cipher_len = 0;

    FILE *f = fopen("cipher.bin", "rb");
    if (!f) {
        perror("cipher.bin 열기 실패");
        return 1;
    }
    cipher_len = fread(ciphertext, 1, MAX_BUF_SIZE, f);
    fclose(f);

    printf("Read %zu bytes from cipher.bin\n", cipher_len);

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

    TEEC_SharedMemory in, out;
    in.size = cipher_len;
    in.flags = TEEC_MEM_INPUT;
    res = TEEC_AllocateSharedMemory(&ctx, &in);
    if (res != TEEC_SUCCESS) {
        printf("AllocateSharedMemory (in) failed: 0x%x\n", res);
        goto cleanup;
    }
    memcpy(in.buffer, ciphertext, cipher_len);

    out.size = MAX_BUF_SIZE;
    out.flags = TEEC_MEM_OUTPUT;
    res = TEEC_AllocateSharedMemory(&ctx, &out);
    if (res != TEEC_SUCCESS) {
        printf("AllocateSharedMemory (out) failed: 0x%x\n", res);
        goto cleanup_free_in;
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

    res = TEEC_InvokeCommand(&sess, CMD_RSA_DECRYPT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand (decrypt) failed: 0x%x (origin: 0x%x)\n", res, err_origin);
    } else {
        printf("Decryption result (%zu bytes):\n", op.params[1].memref.size);
        fwrite(out.buffer, 1, op.params[1].memref.size, stdout);
        printf("\n");
    }

    TEEC_ReleaseSharedMemory(&out);
cleanup_free_in:
    TEEC_ReleaseSharedMemory(&in);
cleanup:
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}

# Toolchain
CC      ?= $(CROSS_COMPILE)gcc

# 파일 목록 (추가 가능)
SRCS_ENCRYPT := host_rsa_encrypt.c
SRCS_DECRYPT := host_rsa_decrypt.c

OBJS_ENCRYPT := $(SRCS_ENCRYPT:.c=.o)
OBJS_DECRYPT := $(SRCS_DECRYPT:.c=.o)

BIN_ENCRYPT := host_rsa_encrypt
BIN_DECRYPT := host_rsa_decrypt

# Include & lib 경로 설정
INCLUDES := -I../ta/include -I$(TEEC_EXPORT)/include -I./include
LIBS     := -L$(TEEC_EXPORT)/lib -lteec

CFLAGS += -Wall $(INCLUDES)
LDFLAGS += $(LIBS)

# 전체 타깃
.PHONY: all clean
all: $(BIN_ENCRYPT) $(BIN_DECRYPT)

# 개별 바이너리 생성
$(BIN_ENCRYPT): $(OBJS_ENCRYPT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN_DECRYPT): $(OBJS_DECRYPT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# .o 파일 생성 규칙
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 정리
clean:
	rm -f *.o $(BIN_ENCRYPT) $(BIN_DECRYPT)

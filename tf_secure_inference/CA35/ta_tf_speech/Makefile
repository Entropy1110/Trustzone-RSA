export V?=0


ENV ?= "TA_DEV_KIT_DIR=$(SDKTARGETSYSROOT)/usr/include/optee/export-user_ta_arm64 LIBGCC_LOCATE_CFLAGS=--sysroot=$(SDKTARGETSYSROOT) TEEC_EXPORT=$(SDKTARGETSYSROOT)/usr libgccta=$(SDKTARGETSYSROOT)/lib/aarch64-ostl-linux/13.3.0/libgcc.a libgccta_arm64=$(SDKTARGETSYSROOT)/lib/aarch64-ostl-linux/13.3.0/libgcc.a"

# If _HOST or _TA specific compilers are not specified, then use CROSS_COMPILE
HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)
TA_CROSS_COMPILE ?= $(CROSS_COMPILE)

.PHONY: all
all:
	$(MAKE) "$(ENV)" -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables
	$(MAKE) "$(ENV)" -C ta CROSS_COMPILE="$(TA_CROSS_COMPILE)" LDFLAGS=""

.PHONY: clean
clean:
	$(MAKE) "$(ENV)" -C host clean
	$(MAKE) "$(ENV)" -C ta clean

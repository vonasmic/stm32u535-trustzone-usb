################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (14.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
C:/tmp/SE_firmware/wolfboot-2.9.0/lib/wolfPKCS11/src/crypto.c \
C:/tmp/SE_firmware/wolfboot-2.9.0/lib/wolfPKCS11/src/internal.c \
C:/tmp/SE_firmware/wolfboot-2.9.0/lib/wolfPKCS11/src/slot.c \
C:/tmp/SE_firmware/wolfboot-2.9.0/lib/wolfPKCS11/src/wolfpkcs11.c 

OBJS += \
./wolfBoot/wolfPKCS11/crypto.o \
./wolfBoot/wolfPKCS11/internal.o \
./wolfBoot/wolfPKCS11/slot.o \
./wolfBoot/wolfPKCS11/wolfpkcs11.o 

C_DEPS += \
./wolfBoot/wolfPKCS11/crypto.d \
./wolfBoot/wolfPKCS11/internal.d \
./wolfBoot/wolfPKCS11/slot.d \
./wolfBoot/wolfPKCS11/wolfpkcs11.d 


# Each subdirectory must supply rules for building sources it contributes
wolfBoot/wolfPKCS11/crypto.o: C:/tmp/SE_firmware/wolfboot-2.9.0/lib/wolfPKCS11/src/crypto.c wolfBoot/wolfPKCS11/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m33 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32U535xx -DWOLFSSL_USER_SETTINGS -DWOLFPKCS11_USER_SETTINGS -DSECURE_PKCS11 -c -I../wolfSSL -I../Core/Inc -I../../Secure_nsclib -I../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/ -I../../Drivers/STM32U5xx_HAL_Driver/Inc -I../../Drivers/CMSIS/Device/ST/STM32U5xx/Include -I../../Drivers/STM32U5xx_HAL_Driver/Inc/Legacy -I../../Drivers/CMSIS/Include -I../../wolfboot-2.9.0/include -I../../wolfboot-2.9.0/lib/wolfPKCS11 -Os -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -mcmse -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -o "$@"
wolfBoot/wolfPKCS11/internal.o: C:/tmp/SE_firmware/wolfboot-2.9.0/lib/wolfPKCS11/src/internal.c wolfBoot/wolfPKCS11/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m33 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32U535xx -DWOLFSSL_USER_SETTINGS -DWOLFPKCS11_USER_SETTINGS -DSECURE_PKCS11 -c -I../wolfSSL -I../Core/Inc -I../../Secure_nsclib -I../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/ -I../../Drivers/STM32U5xx_HAL_Driver/Inc -I../../Drivers/CMSIS/Device/ST/STM32U5xx/Include -I../../Drivers/STM32U5xx_HAL_Driver/Inc/Legacy -I../../Drivers/CMSIS/Include -I../../wolfboot-2.9.0/include -I../../wolfboot-2.9.0/lib/wolfPKCS11 -Os -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -mcmse -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -o "$@"
wolfBoot/wolfPKCS11/slot.o: C:/tmp/SE_firmware/wolfboot-2.9.0/lib/wolfPKCS11/src/slot.c wolfBoot/wolfPKCS11/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m33 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32U535xx -DWOLFSSL_USER_SETTINGS -DWOLFPKCS11_USER_SETTINGS -DSECURE_PKCS11 -c -I../wolfSSL -I../Core/Inc -I../../Secure_nsclib -I../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/ -I../../Drivers/STM32U5xx_HAL_Driver/Inc -I../../Drivers/CMSIS/Device/ST/STM32U5xx/Include -I../../Drivers/STM32U5xx_HAL_Driver/Inc/Legacy -I../../Drivers/CMSIS/Include -I../../wolfboot-2.9.0/include -I../../wolfboot-2.9.0/lib/wolfPKCS11 -Os -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -mcmse -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -o "$@"
wolfBoot/wolfPKCS11/wolfpkcs11.o: C:/tmp/SE_firmware/wolfboot-2.9.0/lib/wolfPKCS11/src/wolfpkcs11.c wolfBoot/wolfPKCS11/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m33 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32U535xx -DWOLFSSL_USER_SETTINGS -DWOLFPKCS11_USER_SETTINGS -DSECURE_PKCS11 -c -I../wolfSSL -I../Core/Inc -I../../Secure_nsclib -I../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/ -I../../Drivers/STM32U5xx_HAL_Driver/Inc -I../../Drivers/CMSIS/Device/ST/STM32U5xx/Include -I../../Drivers/STM32U5xx_HAL_Driver/Inc/Legacy -I../../Drivers/CMSIS/Include -I../../wolfboot-2.9.0/include -I../../wolfboot-2.9.0/lib/wolfPKCS11 -Os -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -mcmse -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-wolfBoot-2f-wolfPKCS11

clean-wolfBoot-2f-wolfPKCS11:
	-$(RM) ./wolfBoot/wolfPKCS11/crypto.cyclo ./wolfBoot/wolfPKCS11/crypto.d ./wolfBoot/wolfPKCS11/crypto.o ./wolfBoot/wolfPKCS11/crypto.su ./wolfBoot/wolfPKCS11/internal.cyclo ./wolfBoot/wolfPKCS11/internal.d ./wolfBoot/wolfPKCS11/internal.o ./wolfBoot/wolfPKCS11/internal.su ./wolfBoot/wolfPKCS11/slot.cyclo ./wolfBoot/wolfPKCS11/slot.d ./wolfBoot/wolfPKCS11/slot.o ./wolfBoot/wolfPKCS11/slot.su ./wolfBoot/wolfPKCS11/wolfpkcs11.cyclo ./wolfBoot/wolfPKCS11/wolfpkcs11.d ./wolfBoot/wolfPKCS11/wolfpkcs11.o ./wolfBoot/wolfPKCS11/wolfpkcs11.su

.PHONY: clean-wolfBoot-2f-wolfPKCS11


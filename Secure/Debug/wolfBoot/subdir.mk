################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (14.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
C:/tmp/SE_firmware/wolfboot-2.9.0/src/pkcs11_callable.c 

OBJS += \
./wolfBoot/pkcs11_callable.o 

C_DEPS += \
./wolfBoot/pkcs11_callable.d 


# Each subdirectory must supply rules for building sources it contributes
wolfBoot/pkcs11_callable.o: C:/tmp/SE_firmware/wolfboot-2.9.0/src/pkcs11_callable.c wolfBoot/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m33 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32U535xx -DWOLFSSL_USER_SETTINGS -DWOLFPKCS11_USER_SETTINGS -DSECURE_PKCS11 -c -I../wolfSSL -I../Core/Inc -I../../Secure_nsclib -I../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/ -I../../Drivers/STM32U5xx_HAL_Driver/Inc -I../../Drivers/CMSIS/Device/ST/STM32U5xx/Include -I../../Drivers/STM32U5xx_HAL_Driver/Inc/Legacy -I../../Drivers/CMSIS/Include -I../../wolfboot-2.9.0/include -I../../wolfboot-2.9.0/lib/wolfPKCS11 -Os -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -mcmse -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-wolfBoot

clean-wolfBoot:
	-$(RM) ./wolfBoot/pkcs11_callable.cyclo ./wolfBoot/pkcs11_callable.d ./wolfBoot/pkcs11_callable.o ./wolfBoot/pkcs11_callable.su

.PHONY: clean-wolfBoot


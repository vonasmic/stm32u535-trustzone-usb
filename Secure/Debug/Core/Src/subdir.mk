################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (14.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Core/Src/main.c \
../Core/Src/se_nv.c \
../Core/Src/se_tls_client.c \
../Core/Src/se_tls_nsc_callable.c \
../Core/Src/se_tropic.c \
../Core/Src/se_tropic_mlkem.c \
../Core/Src/se_tropic_pin.c \
../Core/Src/se_tropic_port_stm32.c \
../Core/Src/se_tropic_rmem.c \
../Core/Src/se_tropic_session.c \
../Core/Src/se_usb_tls.c \
../Core/Src/secure_client_key.c \
../Core/Src/secure_nsc.c \
../Core/Src/secure_otp.c \
../Core/Src/secure_qkd_ingest.c \
../Core/Src/secure_wrap.c \
../Core/Src/stm32u5xx_hal_msp.c \
../Core/Src/stm32u5xx_it.c \
../Core/Src/syscalls.c \
../Core/Src/sysmem.c \
../Core/Src/system_stm32u5xx_s.c \
../Core/Src/wc_port_time.c 

OBJS += \
./Core/Src/main.o \
./Core/Src/se_nv.o \
./Core/Src/se_tls_client.o \
./Core/Src/se_tls_nsc_callable.o \
./Core/Src/se_tropic.o \
./Core/Src/se_tropic_mlkem.o \
./Core/Src/se_tropic_pin.o \
./Core/Src/se_tropic_port_stm32.o \
./Core/Src/se_tropic_rmem.o \
./Core/Src/se_tropic_session.o \
./Core/Src/se_usb_tls.o \
./Core/Src/secure_client_key.o \
./Core/Src/secure_nsc.o \
./Core/Src/secure_otp.o \
./Core/Src/secure_qkd_ingest.o \
./Core/Src/secure_wrap.o \
./Core/Src/stm32u5xx_hal_msp.o \
./Core/Src/stm32u5xx_it.o \
./Core/Src/syscalls.o \
./Core/Src/sysmem.o \
./Core/Src/system_stm32u5xx_s.o \
./Core/Src/wc_port_time.o 

C_DEPS += \
./Core/Src/main.d \
./Core/Src/se_nv.d \
./Core/Src/se_tls_client.d \
./Core/Src/se_tls_nsc_callable.d \
./Core/Src/se_tropic.d \
./Core/Src/se_tropic_mlkem.d \
./Core/Src/se_tropic_pin.d \
./Core/Src/se_tropic_port_stm32.d \
./Core/Src/se_tropic_rmem.d \
./Core/Src/se_tropic_session.d \
./Core/Src/se_usb_tls.d \
./Core/Src/secure_client_key.d \
./Core/Src/secure_nsc.d \
./Core/Src/secure_otp.d \
./Core/Src/secure_qkd_ingest.d \
./Core/Src/secure_wrap.d \
./Core/Src/stm32u5xx_hal_msp.d \
./Core/Src/stm32u5xx_it.d \
./Core/Src/syscalls.d \
./Core/Src/sysmem.d \
./Core/Src/system_stm32u5xx_s.d \
./Core/Src/wc_port_time.d 


# Each subdirectory must supply rules for building sources it contributes
Core/Src/%.o Core/Src/%.su Core/Src/%.cyclo: ../Core/Src/%.c Core/Src/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m33 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32U535xx -DWOLFSSL_USER_SETTINGS -DLT_USE_WOLFCRYPT=1 -DLT_HELPERS=1 -DLT_SILICON_REV_ACAB=1 -DLT_LOG_ENABLE_DEBUG=0 -DLT_LOG_ENABLE_INFO=0 -DLT_LOG_ENABLE_WARN=0 -DLT_LOG_ENABLE_ERROR=0 -DLT_CRC_ERR_RETRY_ATTEMPTS=3 -DLT_L1_READ_MAX_TRIES=50 -DLT_L1_READ_RETRY_DELAY_MS=25 -DLT_L1_SPI_TIMEOUT_MS=70 -DLT_L1_INT_TIMEOUT_MS=200 -c -I../wolfSSL -I../Core/Inc -I../../Secure_nsclib -I../../libtropic/include -I../../libtropic/src -I../../libtropic/cal/wolfcrypt -I../../libtropic/hal/stm32/stm32u5xx -I../../Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/wolfssl/ -I../../Drivers/STM32U5xx_HAL_Driver/Inc -I../../Drivers/CMSIS/Device/ST/STM32U5xx/Include -I../../Drivers/STM32U5xx_HAL_Driver/Inc/Legacy -I../../Drivers/CMSIS/Include -Os -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -mcmse -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-Core-2f-Src

clean-Core-2f-Src:
	-$(RM) ./Core/Src/main.cyclo ./Core/Src/main.d ./Core/Src/main.o ./Core/Src/main.su ./Core/Src/se_nv.cyclo ./Core/Src/se_nv.d ./Core/Src/se_nv.o ./Core/Src/se_nv.su ./Core/Src/se_tls_client.cyclo ./Core/Src/se_tls_client.d ./Core/Src/se_tls_client.o ./Core/Src/se_tls_client.su ./Core/Src/se_tls_nsc_callable.cyclo ./Core/Src/se_tls_nsc_callable.d ./Core/Src/se_tls_nsc_callable.o ./Core/Src/se_tls_nsc_callable.su ./Core/Src/se_tropic.cyclo ./Core/Src/se_tropic.d ./Core/Src/se_tropic.o ./Core/Src/se_tropic.su ./Core/Src/se_tropic_mlkem.cyclo ./Core/Src/se_tropic_mlkem.d ./Core/Src/se_tropic_mlkem.o ./Core/Src/se_tropic_mlkem.su ./Core/Src/se_tropic_pin.cyclo ./Core/Src/se_tropic_pin.d ./Core/Src/se_tropic_pin.o ./Core/Src/se_tropic_pin.su ./Core/Src/se_tropic_port_stm32.cyclo ./Core/Src/se_tropic_port_stm32.d ./Core/Src/se_tropic_port_stm32.o ./Core/Src/se_tropic_port_stm32.su ./Core/Src/se_tropic_rmem.cyclo ./Core/Src/se_tropic_rmem.d ./Core/Src/se_tropic_rmem.o ./Core/Src/se_tropic_rmem.su ./Core/Src/se_tropic_session.cyclo ./Core/Src/se_tropic_session.d ./Core/Src/se_tropic_session.o ./Core/Src/se_tropic_session.su ./Core/Src/se_usb_tls.cyclo ./Core/Src/se_usb_tls.d ./Core/Src/se_usb_tls.o ./Core/Src/se_usb_tls.su ./Core/Src/secure_client_key.cyclo ./Core/Src/secure_client_key.d ./Core/Src/secure_client_key.o ./Core/Src/secure_client_key.su ./Core/Src/secure_nsc.cyclo ./Core/Src/secure_nsc.d ./Core/Src/secure_nsc.o ./Core/Src/secure_nsc.su ./Core/Src/secure_otp.cyclo ./Core/Src/secure_otp.d ./Core/Src/secure_otp.o ./Core/Src/secure_otp.su ./Core/Src/secure_qkd_ingest.cyclo ./Core/Src/secure_qkd_ingest.d ./Core/Src/secure_qkd_ingest.o ./Core/Src/secure_qkd_ingest.su ./Core/Src/secure_wrap.cyclo ./Core/Src/secure_wrap.d ./Core/Src/secure_wrap.o ./Core/Src/secure_wrap.su ./Core/Src/stm32u5xx_hal_msp.cyclo ./Core/Src/stm32u5xx_hal_msp.d ./Core/Src/stm32u5xx_hal_msp.o ./Core/Src/stm32u5xx_hal_msp.su ./Core/Src/stm32u5xx_it.cyclo ./Core/Src/stm32u5xx_it.d ./Core/Src/stm32u5xx_it.o ./Core/Src/stm32u5xx_it.su ./Core/Src/syscalls.cyclo ./Core/Src/syscalls.d ./Core/Src/syscalls.o ./Core/Src/syscalls.su ./Core/Src/sysmem.cyclo ./Core/Src/sysmem.d ./Core/Src/sysmem.o ./Core/Src/sysmem.su ./Core/Src/system_stm32u5xx_s.cyclo ./Core/Src/system_stm32u5xx_s.d ./Core/Src/system_stm32u5xx_s.o ./Core/Src/system_stm32u5xx_s.su ./Core/Src/wc_port_time.cyclo ./Core/Src/wc_port_time.d ./Core/Src/wc_port_time.o ./Core/Src/wc_port_time.su

.PHONY: clean-Core-2f-Src


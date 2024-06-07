cmake_minimum_required(VERSION 3.22.1)
project(TPE_Protos C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-std=c11 -pedantic -pedantic-errors -g -Wall -Werror -Wextra -D_POSIX_C_SOURCE=200112L -fsanitize=address -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function")

add_executable(TPE_Protos src/main.c
        src/args.c
        src/selector.c
        src/smtp.c
        src/smtp.h
        src/stm.c
        src/stm.h)

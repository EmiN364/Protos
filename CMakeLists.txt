cmake_minimum_required(VERSION 3.28)
project(TPE_Protos C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-pedantic -pedantic-errors -g -Wall -Werror -Wextra -D_POSIX_C_SOURCE=200112L -fsanitize=address")

add_executable(TPE_Protos main.c
        args.c)

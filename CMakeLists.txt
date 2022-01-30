cmake_minimum_required(VERSION 3.18)
project(masscan)

set(CMAKE_C_COMPILER /usr/bin/clang)
set(CMAKE_CXX_COMPILER /usr/bin/clang++)

set(CMAKE_CXX_STANDARD 20)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(BASE_FLAGS "-g3 -Wall -fvisibility=hidden -fvisibility-inlines-hidden")
set(DEBUG_FLAGS "-Og")
set(RELEASE_FLAGS "-O3 -Ofast -funroll-loops -fno-signed-zeros -fno-trapping-math -march=native -mtune=native -flto=full")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${BASE_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${DEBUG_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} ${RELEASE_FLAGS}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${BASE_FLAGS} -Wextra -fno-rtti")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${RELEASE_FLAGS} -fforce-emit-vtables -fstrict-vtable-pointers -fwhole-program-vtables")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-v,--build-id=none,--exclude-libs,ALL,--icf=all,--gc-sections -fuse-ld=gold -lm -lrt -ldl -lpthread")

file(GLOB SRC CONFIGURE_DEPENDS "src/*.h" "src/*.cpp" "src/*.c")

add_executable(${PROJECT_NAME} ${SRC})
add_custom_command(
        TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} ARGS --only-keep-debug ${PROJECT_NAME} ${PROJECT_NAME}.dbg
        COMMAND ${CMAKE_STRIP} ARGS --strip-all ${PROJECT_NAME}
        COMMAND ${CMAKE_OBJCOPY} ARGS --add-gnu-debuglink=${PROJECT_NAME}.dbg ${PROJECT_NAME}
)

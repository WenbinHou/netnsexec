cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(netnsexec
        LANGUAGES C)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES netnsexec.c netnsexec.h version.h)

add_executable(netnsexec ${SOURCE_FILES})
target_link_libraries(netnsexec PUBLIC "-static")


#add_custom_command(
#        TARGET netnsexec
#        POST_BUILD
#        COMMAND /usr/bin/sudo chown root:root $<TARGET_FILE:netnsexec>
#        COMMENT "chown root:root"
#        VERBATIM)
#
#add_custom_command(
#        TARGET netnsexec
#        POST_BUILD
#        COMMAND /usr/bin/sudo chmod u+s $<TARGET_FILE:netnsexec>
#        COMMENT "chmod u+s"
#        VERBATIM)

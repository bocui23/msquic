# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function(add_quic_tool)
    set(targetname ${ARGV0})
    list(REMOVE_AT ARGV 0)

    add_executable(${targetname} ${ARGV})
    target_link_libraries(${targetname} inc warnings msquic)

    if (BUILD_SHARED_LIBS)
        target_link_libraries(${targetname} platform)
    endif()


    find_library(QUIC_CRYPTO_LIB quic_crypto_s HINTS /home/bcui/github/local_lib)
    find_library(QAT_LIB qat_s HINTS /home/bcui/github/local_lib)

    #set_target_properties(${MY_3RD_PARTY_LIB} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/3rd_party_libs)

    target_link_libraries(${targetname} logging base_link ${QUIC_CRYPTO_LIB} ${QAT_LIB})

    set_property(TARGET ${targetname} PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tools")
endfunction()

function(quic_tool_warnings)
    target_link_libraries(${ARGV0} warnings)
endfunction()

add_subdirectory(attack)
add_subdirectory(interop)
add_subdirectory(interopserver)
add_subdirectory(ip/client)
add_subdirectory(ip/server)
add_subdirectory(lb)
add_subdirectory(load)
add_subdirectory(pcp)
add_subdirectory(post)
add_subdirectory(sample)
add_subdirectory(spin)
if(WIN32 AND (NOT QUIC_UWP_BUILD AND NOT QUIC_GAMECORE_BUILD))
    add_subdirectory(etw)
endif()

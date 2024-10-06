get_filename_component(TLSSERVERHELPERS_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)

list(APPEND CMAKE_MODULE_PATH ${TLSSERVERHELPERS_CMAKE_DIR})

include(CMakeFindDependencyMacro)
find_dependency(LibreSSL)

if(NOT TARGET wwa_tlsserverhelpers)
    include("${TLSSERVERHELPERS_CMAKE_DIR}/wwa_tlsserverhelpers-target.cmake")
    add_library(wwa::TLSServerHelpers ALIAS wwa_tlsserverhelpers)
endif()

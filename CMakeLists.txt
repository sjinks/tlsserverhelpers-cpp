cmake_minimum_required(VERSION 3.23)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(
    wwa_tlsserverhelpers
    VERSION 1.0.0
    DESCRIPTION "TLS server helpers library"
    HOMEPAGE_URL "https://github.com/sjinks/tlsserverhelpers-cpp"
    LANGUAGES CXX
)

set(CMAKE_VERBOSE_MAKEFILE ON)

option(INSTALL_TLSHELPERS "Whether to install TLS Helpers" ON)

find_package(LibreSSL CONFIG REQUIRED)

add_library(${PROJECT_NAME})

set(HEADERS
    src/export.h
    src/tlsconfigurator.h
    src/tlscontext.h
    src/tlsexception.h
    src/tlsservercontext.h
)

set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
        PUBLIC_HEADER "${HEADERS}"
        INTERFACE_COMPILE_FEATURES cxx_std_20
)

target_sources(
    ${PROJECT_NAME}
    PRIVATE
        src/tlsconfigurator.cpp
        src/tlscontext.cpp
        src/tlsservercontext.cpp
)

if(NOT BUILD_SHARED_LIBS)
    target_compile_definitions(${PROJECT_NAME} PUBLIC WWA_TLS_SERVER_HELPERS_STATIC_DEFINE)
endif()

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
)

target_link_libraries(${PROJECT_NAME} PUBLIC LibreSSL::TLS)

if(INSTALL_TLSHELPERS)
    include(CMakePackageConfigHelpers)
    include(GNUInstallDirs)

    install(
        TARGETS ${PROJECT_NAME}
        EXPORT ${PROJECT_NAME}-target
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tlsserverhelpers"
    )

    install(
        EXPORT ${PROJECT_NAME}-target
        FILE ${PROJECT_NAME}-target.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
    )

    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY AnyNewerVersion
    )

    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/${PROJECT_NAME}-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
        COPYONLY
    )

    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
            ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
    )

    if(BUILD_SHARED_LIBS)
        set(REQUIRES_SUFFIX ".private")
    endif()
    configure_file("${CMAKE_SOURCE_DIR}/cmake/pkg-config.pc.in" "${PROJECT_NAME}.pc" @ONLY)
    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
    )
endif()

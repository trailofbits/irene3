string(TOLOWER "${PROJECT_NAME}" lower_project_name)
set(IRENE3_EXAMINE "${lower_project_name}-examine-spec")
set(IRENE3_EXAMINE
    "${IRENE3_EXAMINE}"
    PARENT_SCOPE
)

add_executable("${IRENE3_EXAMINE}" Main.cpp)

set_target_properties("${IRENE3_EXAMINE}" PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries("${IRENE3_EXAMINE}" PRIVATE irene3)
target_include_directories(
    "${IRENE3_EXAMINE}" PRIVATE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>"
)

if(IRENE3_ENABLE_INSTALL)
    install(
        TARGETS "${IRENE3_EXAMINE}"
        EXPORT irene3Targets
        RUNTIME DESTINATION bin
    )
endif(IRENE3_ENABLE_INSTALL)

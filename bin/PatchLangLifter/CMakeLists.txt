string(TOLOWER "${PROJECT_NAME}" lower_project_name)
set(IRENE3_PATCHLANGLIFT "${lower_project_name}-patchlang-lift")
set(IRENE3_PATCHLANGLIFT
    "${IRENE3_PATCHLANGLIFT}"
    PARENT_SCOPE
)

add_executable("${IRENE3_PATCHLANGLIFT}" Main.cpp)

set_target_properties("${IRENE3_PATCHLANGLIFT}" PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries("${IRENE3_PATCHLANGLIFT}" PRIVATE irene3 PatchIR MLIRLLVMDialect MLIRLLVMIRToLLVMTranslation)
target_include_directories(
    "${IRENE3_PATCHLANGLIFT}" PRIVATE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>"
)

if(IRENE3_ENABLE_INSTALL)
    install(
        TARGETS "${IRENE3_PATCHLANGLIFT}"
        EXPORT irene3Targets
        RUNTIME DESTINATION bin
    )
endif(IRENE3_ENABLE_INSTALL)

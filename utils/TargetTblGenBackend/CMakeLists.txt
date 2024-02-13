string(TOLOWER "${PROJECT_NAME}" lower_project_name)
set(IRENE3_GENERATE_TARGET "${lower_project_name}-generate-target")
set(IRENE3_GENERATE_TARGET
    "${IRENE3_GENERATE_TARGET}"
    PARENT_SCOPE
)

add_executable("${IRENE3_GENERATE_TARGET}" Main.cpp)

llvm_map_components_to_libnames(llvm_libs TableGen)

set_target_properties("${IRENE3_GENERATE_TARGET}" PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries("${IRENE3_GENERATE_TARGET}" PRIVATE "${llvm_libs}" glog::glog)
target_include_directories(
    "${IRENE3_GENERATE_TARGET}" PRIVATE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>"
)

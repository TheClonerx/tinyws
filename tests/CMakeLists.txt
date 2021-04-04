
function(add_tinyws_test test_name)
    set(target_name "tinyws_tests_${test_name}")
    set(test_list "${test_list} ${target_name}" PARENT_SCOPE)
    add_executable(${target_name})
    target_link_libraries(${target_name} PRIVATE tinyws_a)
    target_sources(${target_name} PRIVATE "${CMAKE_CURRENT_LIST_DIR}/${test_name}.c")
    add_test(NAME "test_${test_name}" COMMAND $<TARGET_FILE:${target_name}>)
endfunction(add_tinyws_test)

add_tinyws_test(byte_masking)

add_custom_target(tests COMMAND run_tests DEPENDS ${test_list})

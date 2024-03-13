# unit parser serializer xpath json crypto http processor webapp soap rest security uri
list(APPEND PINCH_tests
	# coro
	service
	# sftp
	# unit
)

foreach(TEST IN LISTS PINCH_tests)
	set(PINCH_TEST "${TEST}-test")
	set(PINCH_TEST_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/${PINCH_TEST}.cpp")

	add_executable(${PINCH_TEST} ${PINCH_TEST_SOURCE})
	target_link_libraries(${PINCH_TEST} PRIVATE pinch)

	if(MSVC)
		# Specify unwind semantics so that MSVC knowns how to handle exceptions
		target_compile_options(${PINCH_TEST} PRIVATE /EHsc)
	endif()

	if(${TEST} STREQUAL "sftp")
		set(${PINCH_TEST_ARGS} "localhost 22 maarten")
	else()
		set(${PINCH_TEST_ARGS} "")
	endif()

	add_test(NAME ${PINCH_TEST}
		COMMAND $<TARGET_FILE:${PINCH_TEST}> ${PINCH_TEST_ARGS}
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/test)
endforeach()
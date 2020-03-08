cmake_minimum_required(VERSION 2.8)
project(cors-relay)
set(CMAKE_C_STANDARD 99)

# using git version
find_package(Git)
execute_process(COMMAND ${GIT_EXECUTABLE} describe --abbrev=6 --dirty --always --tags
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE  GIT_REPO_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(COMMAND ${GIT_EXECUTABLE} log -1 --format=%cd --date=short
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE  GIT_REPO_DATE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
file(WRITE ${PROJECT_BINARY_DIR}/repo_version.h
    "#define REPO_VERSION \"${GIT_REPO_VERSION}\"\n#define REPO_DATE \"${GIT_REPO_DATE}\"\n"
)
include_directories(${PROJECT_BINARY_DIR})

add_subdirectory(wsocket)
add_subdirectory(libfort)
add_subdirectory(ulog)

if(WIN32)
	set(SRC ntripcaster.c base64.c proxy_cluster.c geohash.c tokens.c evwrap.c)
	set(LIBS wsocket fort ulog sqlite3)
else()
	set(SRC ntripcaster.c base64.c proxy_cluster.c geohash.c tokens.c)
	set(LIBS wsocket fort ulog sqlite3 ev m)
endif()

add_executable(${PROJECT_NAME} ${SRC})
target_link_libraries(${PROJECT_NAME} ${LIBS})


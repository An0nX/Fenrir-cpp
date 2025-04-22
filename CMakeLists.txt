cmake_minimum_required(VERSION 3.16) # Need C++17 for filesystem
project(FenrirCPP CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF) # Avoid GNU extensions if possible for portability

# --- Hardening Flags ---
set(HARDENING_FLAGS "-fstack-protector-all -D_FORTIFY_SOURCE=2")
set(PIE_FLAGS "-fPIE -pie")
set(LINKER_HARDENING_FLAGS "-Wl,-z,relro,-z,now")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${HARDENING_FLAGS} -O2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${HARDENING_FLAGS} -O2")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${PIE_FLAGS} ${LINKER_HARDENING_FLAGS}")

# --- Static Linking Preference ---
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ${CMAKE_FIND_LIBRARY_SUFFIXES})

# --- Find Required Libraries (Requesting Static) ---
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(MAGIC REQUIRED libmagic) # Finds libmagic info via pkg-config
# <<< УДАЛЕНО: find_package(Zstd REQUIRED) >>>

# --- Check Static Status and Define Targets/Paths ---
set(FOUND_STATIC_OPENSSL FALSE)
if(TARGET OpenSSL::libcrypto_static AND TARGET OpenSSL::libssl_static)
    set(OPENSSL_LIBS OpenSSL::libssl_static OpenSSL::libcrypto_static)
    set(FOUND_STATIC_OPENSSL TRUE)
    message(STATUS "Found static OpenSSL targets.")
else()
    set(OPENSSL_LIBS OpenSSL::SSL OpenSSL::Crypto) # Fallback (likely dynamic)
    message(WARNING "Could not find static OpenSSL targets. Linking might be dynamic.")
endif()

set(FOUND_STATIC_ZLIB FALSE)
if(ZLIB_STATIC_LIBRARY)
    set(ZLIB_LIB ${ZLIB_STATIC_LIBRARY}) # Store path to .a
    set(FOUND_STATIC_ZLIB TRUE)
    message(STATUS "Found static ZLIB library: ${ZLIB_STATIC_LIBRARY}")
else()
    set(ZLIB_LIB ZLIB::ZLIB) # Standard CMake target name (likely dynamic)
    message(WARNING "Could not find static ZLIB library. Linking might be dynamic.")
endif()

set(FOUND_STATIC_BZIP2 FALSE)
if(BZIP2_LIBRARIES_STATIC)
    set(BZIP2_LIB ${BZIP2_LIBRARIES_STATIC}) # Store path to .a
    set(FOUND_STATIC_BZIP2 TRUE)
    message(STATUS "Found static BZip2 library: ${BZIP2_LIBRARIES_STATIC}")
else()
    set(BZIP2_LIB BZip2::BZip2) # Standard CMake target name (likely dynamic)
    message(WARNING "Could not find static BZip2 library. Linking might be dynamic.")
endif()

# <<< ИЗМЕНЕНО: Используем find_library для Zstd >>>
set(FOUND_STATIC_ZSTD FALSE)
find_library(ZSTD_STATIC_LIBRARY NAMES zstd PATH_SUFFIXES .a)
if(ZSTD_STATIC_LIBRARY)
   set(ZSTD_LIB ${ZSTD_STATIC_LIBRARY}) # Use path
   set(FOUND_STATIC_ZSTD TRUE)
   message(STATUS "Found static Zstandard library: ${ZSTD_STATIC_LIBRARY}")
   mark_as_advanced(ZSTD_STATIC_LIBRARY) # Скрыть из обычного вывода ccmake/cmake-gui
else()
   set(ZSTD_LIB zstd) # Fallback to -lzstd (likely dynamic)
   message(WARNING "Could not find static Zstandard library (libzstd.a). Linking might be dynamic or fail.")
endif()


# --- Handle Libmagic ---
set(FOUND_STATIC_LIBMAGIC FALSE)
set(MAGIC_LIB "")
set(_magic_deps_libs "")

if(MAGIC_STATIC_LIBRARIES)
    set(FOUND_STATIC_LIBMAGIC TRUE)
    set(MAGIC_LIB ${MAGIC_STATIC_LIBRARIES})
    message(STATUS "Found static Libmagic library: ${MAGIC_STATIC_LIBRARIES}")

    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} --static --libs-only-l libmagic
                    OUTPUT_VARIABLE _magic_dep_libs_str OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REPLACE " " ";" _magic_dep_libs_list ${_magic_dep_libs_str})

    foreach(_lib_flag ${_magic_dep_libs_list})
        if(_lib_flag MATCHES "^-l(.*)")
            set(_lib_name ${CMAKE_MATCH_1})
            if(NOT _lib_name STREQUAL "magic")
                if(_lib_name STREQUAL "z" AND FOUND_STATIC_ZLIB)
                   list(APPEND _magic_deps_libs ${ZLIB_LIB})
                elseif(_lib_name STREQUAL "bz2" AND FOUND_STATIC_BZIP2)
                   list(APPEND _magic_deps_libs ${BZIP2_LIB})
                elseif(_lib_name STREQUAL "lzma")
                    find_library(LZMA_STATIC_LIBRARY NAMES lzma PATH_SUFFIXES .a)
                    if(LZMA_STATIC_LIBRARY)
                       message(STATUS "Found static LZMA library: ${LZMA_STATIC_LIBRARY}")
                       list(APPEND _magic_deps_libs ${LZMA_STATIC_LIBRARY})
                    else()
                       message(WARNING "Static LZMA library not found for libmagic dependency. Linking might fail or use dynamic.")
                       list(APPEND _magic_deps_libs lzma)
                    endif()
                    mark_as_advanced(LZMA_STATIC_LIBRARY)
                # <<< УДАЛЕНО: Проверка зависимости от zstd здесь (OpenSSL сам потребует) >>>
                # elseif(_lib_name STREQUAL "zstd" AND FOUND_STATIC_ZSTD)
                #      list(APPEND _magic_deps_libs ${ZSTD_LIB})
                else()
                   list(APPEND _magic_deps_libs ${_lib_name})
                endif()
            endif()
        endif()
    endforeach()
    message(STATUS "Dependencies for static libmagic: ${_magic_deps_libs}")
else()
    message(WARNING "Could not find static Libmagic library. Linking might be dynamic.")
    set(MAGIC_LIB ${MAGIC_LIBRARIES})
endif()


# --- Add Source Files ---
set(SOURCES
    src/main.cpp
    src/config.cpp
    src/ioc_reader.cpp
    src/scanner.cpp
    src/logger.cpp
    src/utils.cpp
    src/hash_utils.cpp
    src/file_checker.cpp
)

# --- Include Directories ---
include_directories(
    src
    ${OPENSSL_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIR}
    ${BZIP2_INCLUDE_DIR}
    ${MAGIC_INCLUDE_DIRS}
    # <<< ИЗМЕНЕНО: Ищем include для Zstd вручную, если find_package не сработал >>>
    # ${Zstd_INCLUDE_DIRS} # Переменная не будет установлена
)
# Попытка найти заголовок zstd.h
find_path(ZSTD_INCLUDE_DIR_MANUAL zstd.h)
if(ZSTD_INCLUDE_DIR_MANUAL)
   include_directories(${ZSTD_INCLUDE_DIR_MANUAL})
   message(STATUS "Found Zstd include directory: ${ZSTD_INCLUDE_DIR_MANUAL}")
else()
   message(WARNING "Could not find zstd.h header. Compilation requiring zstd headers might fail.")
endif()
mark_as_advanced(ZSTD_INCLUDE_DIR_MANUAL)


# --- Create Executable ---
add_executable(fenrir ${SOURCES})

# --- Link Libraries ---
# Link explicitly using paths for static libs where found
target_link_libraries(fenrir PRIVATE
    ${OPENSSL_LIBS}     # Uses targets or fallback
    ${ZLIB_LIB}         # Uses path to .a or target/name
    ${BZIP2_LIB}        # Uses path to .a or target/name
    ${MAGIC_LIB}        # Uses path to libmagic.a or fallback name (-lmagic)
    ${_magic_deps_libs} # Add the resolved paths/names of magic's dependencies
    ${ZSTD_LIB}         # <<< Используем путь к libzstd.a или имя для fallback >>>
    Threads::Threads    # Standard CMake target for pthreads
    dl                  # libdl needed by OpenSSL, etc.
)

# Optional: Add install rule for the binary and default config
# install(TARGETS fenrir DESTINATION bin)
# install(FILES config/fenrir.conf DESTINATION etc RENAME fenrir.conf.default)

# Optional: Add stripping rule after build
add_custom_command(TARGET fenrir POST_BUILD
    COMMAND ${CMAKE_STRIP} $<TARGET_FILE:fenrir>
    COMMENT "Stripping fenrir binary"
)

message(STATUS "Fenrir configured.")
message(STATUS "Static linking preference enabled.")
message(STATUS "Ensure necessary development libraries (libssl-dev, zlib1g-dev, libbz2-dev, libmagic-dev, liblzma-dev, libzstd-dev) are installed.")

# PUFS Utility source files.
set( PUFS_UTIL_SOURCES
     "${CMAKE_CURRENT_LIST_DIR}/source/pufs_util_pem.c"
     "${CMAKE_CURRENT_LIST_DIR}/source/pufs_util_sec.c"
     "${CMAKE_CURRENT_LIST_DIR}/source/pufs_util.c"
     "${CMAKE_CURRENT_LIST_DIR}/source/pufs_util_x509_csr.c")

# PUFS Utility Public Include directories.
set( PUFS_UTIL_INCLUDE_PUBLIC_DIRS
     "${CMAKE_CURRENT_LIST_DIR}/source" )

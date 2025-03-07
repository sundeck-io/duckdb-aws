# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(aws
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
)

duckdb_extension_load(httpfs
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../duckdb_httpfs
        INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/../duckdb_httpfs/extension/httpfs/include
)
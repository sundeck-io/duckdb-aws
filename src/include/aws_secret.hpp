#pragma once

#include "aws_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/main/secret/secret.hpp"

namespace duckdb {

struct CreateAwsSecretFunctions {
public:
	//! Register all CreateSecretFunctions
	static void Register(DatabaseInstance &instance);

	//! WARNING: not thread-safe, to be called on extension initialization once
	static void InitializeCurlCertificates(DatabaseInstance &db);
};

} // namespace duckdb

# JWKS Server with SQLite Integration

This project implements a JWKS (JSON Web Key Set) server in C++ with SQLite database integration. It generates RSA key pairs, stores them in a SQLite database, serves public keys in JWKS format, and provides an authentication endpoint to issue JWTs (JSON Web Tokens).

## Features

- Generates RSA key pairs with unique key IDs (`kid`) and expiry timestamps.
- Stores private keys in a SQLite database (`totally_not_my_privateKeys.db`).
- Serves a JWKS endpoint to provide public keys for JWT verification.
- Provides an `/auth` endpoint to issue signed JWTs.
- Handles the issuance of JWTs with expired keys based on a query parameter.
- Only serves keys that have not expired.

## Requirements

- C++ compiler with C++11 support
- CMake 3.14 or higher
- OpenSSL development libraries
- SQLite3 development libraries
- Internet connection to fetch dependencies

## Dependencies

- [jwt-cpp](https://github.com/Thalhammer/jwt-cpp)
- [cpp-httplib](https://github.com/yhirose/cpp-httplib)
- [SQLite3](https://www.sqlite.org/index.html)
- [GoogleTest](https://github.com/google/googletest)
- OpenSSL libraries

The dependencies are automatically fetched using CMake's `FetchContent` module.

## Building the Project

### Clone the Repository

```bash
git clone https://github.com/yourusername/jwks_server.git
cd jwks_server

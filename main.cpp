#include <iostream>
#include <string>
#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <chrono>
#include <ctime>
#include <sqlite3.h>
#include <vector>

// Database file name
const std::string DB_FILE = "totally_not_my_privateKeys.db";

// Key structure
struct Key {
    int kid;
    std::string pem_private_key;
    std::chrono::system_clock::time_point exp;
};

// Function to create/open SQLite database and create table if not exists
void init_database() {
    sqlite3* db;
    char* err_msg = nullptr;

    int rc = sqlite3_open(DB_FILE.c_str(), &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        exit(1);
    }

    const char* sql = "CREATE TABLE IF NOT EXISTS keys("
                      "kid INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "key TEXT NOT NULL,"
                      "exp INTEGER NOT NULL);";

    rc = sqlite3_exec(db, sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error (create table): " << err_msg << std::endl;
        sqlite3_free(err_msg);
        sqlite3_close(db);
        exit(1);
    }

    sqlite3_close(db);
}

// Function to generate a new RSA key pair and return as EVP_PKEY*
EVP_PKEY* generate_rsa_keypair() {
    EVP_PKEY* pkey = nullptr;
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);

    if (RSA_generate_key_ex(rsa, 2048, e, NULL)) {
        pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsa);
    } else {
        RSA_free(rsa);
    }

    BN_free(e);
    return pkey;
}

// Function to get PEM formatted key
std::string get_pem(EVP_PKEY* pkey, bool is_private) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (is_private) {
        PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    } else {
        PEM_write_bio_PUBKEY(bio, pkey);
    }

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string pem_str(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);
    return pem_str;
}

// Function to insert a key into the database
void insert_key_into_db(const std::string& pem_key, std::chrono::system_clock::time_point exp_time) {
    sqlite3* db;
    char* err_msg = nullptr;

    int rc = sqlite3_open(DB_FILE.c_str(), &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Cannot open database (insert): " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        exit(1);
    }

    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO keys(key, exp) VALUES (?, ?);";

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, pem_key.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, std::chrono::system_clock::to_time_t(exp_time));
    } else {
        std::cerr << "Failed to prepare statement (insert)" << std::endl;
        sqlite3_close(db);
        exit(1);
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Failed to execute statement (insert)" << std::endl;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

// Function to retrieve keys from the database
std::vector<Key> get_keys_from_db(bool expired) {
    sqlite3* db;
    sqlite3_open(DB_FILE.c_str(), &db);

    sqlite3_stmt* stmt;
    const char* sql = expired ?
        "SELECT kid, key, exp FROM keys WHERE exp <= ?;" :
        "SELECT kid, key, exp FROM keys WHERE exp > ?;";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement (select)" << std::endl;
        sqlite3_close(db);
        exit(1);
    }

    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    sqlite3_bind_int64(stmt, 1, now);

    std::vector<Key> keys;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        Key key;
        key.kid = sqlite3_column_int(stmt, 0);
        key.pem_private_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        key.exp = std::chrono::system_clock::from_time_t(sqlite3_column_int64(stmt, 2));
        keys.push_back(key);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return keys;
}

// Function to extract public key components n and e for JWKS
void get_rsa_public_numbers_from_pem(const std::string& pem_key, std::string& n_str, std::string& e_str) {
    BIO* bio = BIO_new_mem_buf(pem_key.data(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    RSA_get0_key(rsa, &n, &e, nullptr);

    // Convert BIGNUM to base64url strings
    auto bn_to_base64url = [](const BIGNUM* bn) -> std::string {
        int bn_len = BN_num_bytes(bn);
        unsigned char* bn_bin = new unsigned char[bn_len];
        BN_bn2bin(bn, bn_bin);
        std::string bin_str(reinterpret_cast<char*>(bn_bin), bn_len);
        delete[] bn_bin;
        return jwt::base::encode<jwt::alphabet::base64url>(bin_str);
    };

    n_str = bn_to_base64url(n);
    e_str = bn_to_base64url(e);

    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
}

int main() {
    // Initialize database
    init_database();

    // Generate and store keys (one expired, one valid)
    // Expired key
    {
        EVP_PKEY* pkey = generate_rsa_keypair();
        std::string priv_key_pem = get_pem(pkey, true);
        auto exp_time = std::chrono::system_clock::now() - std::chrono::hours(1);
        insert_key_into_db(priv_key_pem, exp_time);
        EVP_PKEY_free(pkey);
    }

    // Valid key
    {
        EVP_PKEY* pkey = generate_rsa_keypair();
        std::string priv_key_pem = get_pem(pkey, true);
        auto exp_time = std::chrono::system_clock::now() + std::chrono::hours(1);
        insert_key_into_db(priv_key_pem, exp_time);
        EVP_PKEY_free(pkey);
    }

    // Start HTTP server
    httplib::Server svr;

    svr.Post("/auth", [](const httplib::Request& req, httplib::Response& res) {
        // Check if the "expired" query parameter is set
        bool expired = req.has_param("expired");

        // Retrieve keys from DB
        auto keys = get_keys_from_db(expired);

        if (keys.empty()) {
            res.status = 500;
            res.set_content("No keys available", "text/plain");
            return;
        }

        // Use the first key
        Key key = keys[0];

        // Create JWT token
        auto token = jwt::create()
            .set_issuer("auth0")
            .set_type("JWT")
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(key.exp)
            .set_key_id(std::to_string(key.kid))
            .sign(jwt::algorithm::rs256("", key.pem_private_key, "", ""));

        res.set_content(token, "text/plain");
    });

    svr.Get("/.well-known/jwks.json", [](const httplib::Request& req, httplib::Response& res) {
        // Retrieve valid keys from DB
        auto keys = get_keys_from_db(false);

        std::string jwks = R"({"keys":[)";

        for (size_t i = 0; i < keys.size(); ++i) {
            std::string n_str, e_str;
            get_rsa_public_numbers_from_pem(keys[i].pem_private_key, n_str, e_str);

            jwks += R"({"kty":"RSA","use":"sig","kid":")" + std::to_string(keys[i].kid) +
                    R"(","alg":"RS256","n":")" + n_str + R"(","e":")" + e_str + R"("})";

            if (i != keys.size() - 1) {
                jwks += ",";
            }
        }

        jwks += "]}";
        res.set_content(jwks, "application/json");
    });

    // Run server on port 8080
    svr.listen("0.0.0.0", 8080);

    return 0;
}

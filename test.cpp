#include <gtest/gtest.h>
#include <httplib.h>
#include <jwt-cpp/jwt.h>

TEST(JWKSServerTest, ValidJWTAuthentication) {
    httplib::Client cli("http://localhost:8080");
    auto res = cli.Post("/auth");
    ASSERT_EQ(res->status, 200);

    std::string token = res->body;

    // Get JWKS
    auto jwks_res = cli.Get("/.well-known/jwks.json");
    ASSERT_EQ(jwks_res->status, 200);

    auto decoded_jwks = jwt::parse_jwks(jwks_res->body);

    // Verify token
    auto decoded_token = jwt::decode(token);
    auto verifier = jwt::verify()
        .allow_algorithm(jwt::algorithm::rs256("", "", "", ""))
        .with_issuer("auth0");

    verifier.verify(decoded_token, decoded_jwks);
}

TEST(JWKSServerTest, ExpiredJWTAuthentication) {
    httplib::Client cli("http://localhost:8080");
    auto res = cli.Post("/auth?expired=true");
    ASSERT_EQ(res->status, 200);

    std::string token = res->body;

    // Get JWKS
    auto jwks_res = cli.Get("/.well-known/jwks.json");
    ASSERT_EQ(jwks_res->status, 200);

    auto decoded_jwks = jwt::parse_jwks(jwks_res->body);

    // Verify token (should fail due to expiration)
    auto decoded_token = jwt::decode(token);
    auto verifier = jwt::verify()
        .allow_algorithm(jwt::algorithm::rs256("", "", "", ""))
        .with_issuer("auth0");

    EXPECT_THROW(verifier.verify(decoded_token, decoded_jwks), jwt::token_verification_exception);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

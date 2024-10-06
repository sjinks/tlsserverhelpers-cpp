#include <memory>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <tlsserverhelpers/tlsservercontext.h>

constexpr int KEY_SIZE          = 2048;
constexpr long int KEY_VALIDITY = 31'536'000L;

static std::pair<std::unique_ptr<BIO, decltype(&BIO_free)>, std::unique_ptr<BIO, decltype(&BIO_free)>> generate_cert()
{
    std::unique_ptr<RSA, decltype(&RSA_free)> rsa(RSA_new(), &RSA_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(BN_new(), &BN_free);
    BN_set_word(bn.get(), RSA_F4);
    RSA_generate_key_ex(rsa.get(), KEY_SIZE, bn.get(), nullptr);

    std::unique_ptr<BIO, decltype(&BIO_free)> private_bio(BIO_new(BIO_s_mem()), &BIO_free);
    PEM_write_bio_RSAPrivateKey(private_bio.get(), rsa.get(), nullptr, nullptr, 0, nullptr, nullptr);

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_PKEY_new(), &EVP_PKEY_free);
    EVP_PKEY_assign_RSA(pkey.get(), rsa.release());

    std::unique_ptr<X509, decltype(&X509_free)> x509(X509_new(), &X509_free);
    X509_set_version(x509.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509.get()), KEY_VALIDITY);
    X509_set_pubkey(x509.get(), pkey.get());

    X509_NAME* name = X509_get_subject_name(x509.get());
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("US"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(
        name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("My Organization"), -1, -1, 0
    );
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0
    );
    X509_set_issuer_name(x509.get(), name);

    X509_sign(x509.get(), pkey.get(), EVP_sha256());

    std::unique_ptr<BIO, decltype(&BIO_free)> cert_bio(BIO_new(BIO_s_mem()), &BIO_free);
    PEM_write_bio_X509(cert_bio.get(), x509.get());

    return {std::move(private_bio), std::move(cert_bio)};
}

int main()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    auto ctx                           = TLSServerContext::create();
    const auto [private_bio, cert_bio] = generate_cert();

    BUF_MEM* pkey_buf = nullptr;
    BUF_MEM* cert_buf = nullptr;

    BIO_get_mem_ptr(private_bio.get(), &pkey_buf);
    BIO_get_mem_ptr(cert_bio.get(), &cert_buf);

    std::span<const std::uint8_t> private_key(reinterpret_cast<const std::uint8_t*>(pkey_buf->data), pkey_buf->length);
    std::span<const std::uint8_t> cert(reinterpret_cast<const std::uint8_t*>(cert_buf->data), cert_buf->length);

    ctx->set_keypair(cert, private_key);
    ctx->configure();

    EVP_cleanup();
    ERR_free_strings();
    return 0;
}

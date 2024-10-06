#include "tlsservercontext.h"

#include <stdexcept>
#include <tls.h>

#include "tlscontext.h"
#include "tlsexception.h"

std::shared_ptr<TLSServerContext> TLSServerContext::create()
{
    return std::make_shared<TLSServerContext>(TLSServerContext::PrivateTag{});
}

TLSServerContext::TLSServerContext(const TLSServerContext::PrivateTag&)
{
    if (!this->m_context || !this->m_config) {
        throw TLSException("Failed to create TLS context");
    }

    tls_config_prefer_ciphers_server(this->m_config.get());
    tls_config_verify(this->m_config.get());
}

TLSServerContext::~TLSServerContext() = default;

void TLSServerContext::set_ca(std::string_view ca)
{
    if (ca.empty()) [[unlikely]] {
        throw std::invalid_argument("ca must not be empty");
    }

    if (tls_config_set_ca_file(this->m_config.get(), ca.data()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_ca_path(std::string_view path)
{
    if (path.empty()) [[unlikely]] {
        throw std::invalid_argument("path must not be empty");
    }

    if (tls_config_set_ca_path(this->m_config.get(), path.data()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_keypair(std::string_view cert, std::string_view key)
{
    if (cert.empty() || key.empty()) [[unlikely]] {
        throw std::invalid_argument("cert and key must not be empty");
    }

    if (tls_config_set_keypair_file(this->m_config.get(), cert.data(), key.data()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_keypair(std::string_view cert, std::string_view key, std::string_view ocsp)
{
    if (cert.empty() || key.empty() || ocsp.empty()) [[unlikely]] {
        throw std::invalid_argument("cert, key, and ocsp must not be empty");
    }

    if (tls_config_set_keypair_ocsp_file(this->m_config.get(), cert.data(), key.data(), ocsp.data()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_ocsp_staple(std::string_view ocsp)
{
    if (ocsp.empty()) [[unlikely]] {
        throw std::invalid_argument("ocsp must not be empty");
    }

    if (tls_config_set_ocsp_staple_file(this->m_config.get(), ocsp.data()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }

    tls_config_ocsp_require_stapling(this->m_config.get());
}

void TLSServerContext::add_keypair(std::string_view cert, std::string_view key)
{
    if (cert.empty() || key.empty()) [[unlikely]] {
        throw std::invalid_argument("cert and key must not be empty");
    }

    if (tls_config_add_keypair_file(this->m_config.get(), cert.data(), key.data()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::add_keypair(std::string_view cert, std::string_view key, std::string_view ocsp)
{
    if (cert.empty() || key.empty() || ocsp.empty()) [[unlikely]] {
        throw std::invalid_argument("cert, key, and ocsp must not be empty");
    }

    if (tls_config_add_keypair_ocsp_file(this->m_config.get(), cert.data(), key.data(), ocsp.data()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_crl(std::string_view crl)
{
    if (crl.empty()) [[unlikely]] {
        throw std::invalid_argument("crl must not be empty");
    }

    if (tls_config_set_crl_file(this->m_config.get(), crl.data()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_ca(std::span<const std::uint8_t> ca)
{
    // `ca` can be empty; `tls_set_mem()` will clear the data
    if (tls_config_set_ca_mem(this->m_config.get(), ca.data(), ca.size()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_keypair(std::span<const std::uint8_t> cert, std::span<const std::uint8_t> key)
{
    // `cert` and `key` can be empty; `tls_set_mem()` will clear the data
    if (tls_config_set_keypair_mem(this->m_config.get(), cert.data(), cert.size(), key.data(), key.size()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_keypair(
    std::span<const std::uint8_t> cert, std::span<const std::uint8_t> key, std::span<const std::uint8_t> ocsp
)
{
    // `cert`, `key`, and `ocsp` can be empty; `tls_set_mem()` will clear the data
    // !! if `ocsp` is empty, the function will NOT clear the OCSP stapling
    if (tls_config_set_keypair_ocsp_mem(
            this->m_config.get(), cert.data(), cert.size(), key.data(), key.size(), ocsp.data(), ocsp.size()
        ) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_ocsp_staple(std::span<const std::uint8_t> ocsp)
{
    // `ocsp` can be empty; `tls_set_mem()` will clear the data
    if (tls_config_set_ocsp_staple_mem(this->m_config.get(), ocsp.data(), ocsp.size()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::add_keypair(std::span<const std::uint8_t> cert, std::span<const std::uint8_t> key)
{
    // `cert` and `key` can be empty; `tls_set_mem()` will clear the data
    if (tls_config_add_keypair_mem(this->m_config.get(), cert.data(), cert.size(), key.data(), key.size()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::add_keypair(
    std::span<const std::uint8_t> cert, std::span<const std::uint8_t> key, std::span<const std::uint8_t> ocsp
)
{
    // `cert`, `key`, and `ocsp` can be empty
    if (tls_config_add_keypair_ocsp_mem(
            this->m_config.get(), cert.data(), cert.size(), key.data(), key.size(), ocsp.data(), ocsp.size()
        ) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_crl(std::span<const std::uint8_t> crl)
{
    // `crl` can be empty; `tls_set_mem()` will clear the data
    if (tls_config_set_crl_mem(this->m_config.get(), crl.data(), crl.size()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_alpn(std::string_view alpn)
{
    if (alpn.empty()) [[unlikely]] {
        throw std::invalid_argument("alpn must not be empty");
    }

    if (tls_config_set_alpn(this->m_config.get(), alpn.data()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_verify_depth(int depth)
{
    tls_config_set_verify_depth(this->m_config.get(), depth);
}

void TLSServerContext::set_verify_client()
{
    tls_config_verify_client(this->m_config.get());
}

void TLSServerContext::set_verify_client_optional()
{
    tls_config_verify_client_optional(this->m_config.get());
}

void TLSServerContext::enable_dhe()
{
    this->set_dhe_params("auto");
}

/**
 * Default is "none"
 * Valid values: none, auto, legacy
 */
void TLSServerContext::set_dhe_params(std::string_view params)
{
    tls_config_set_dheparams(this->m_config.get(), params.empty() ? "none" : params.data());
}

void TLSServerContext::set_protocols(std::string_view protocols)
{
    std::uint32_t p = TLS_PROTOCOLS_DEFAULT;  // NOLINT(hicpp-signed-bitwise)

    // `protocols` can be empty; `TLS_PROTOCOLS_DEFAULT` will be used
    if (tls_config_parse_protocols(&p, protocols.data()) != 0) {
        throw TLSException("Failed to parse protocols");
    }

    if (tls_config_set_protocols(this->m_config.get(), p) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

/**
 * Default is "secure"
 */
void TLSServerContext::set_ciphers(std::string_view ciphers)
{
    // `ciphers` can be empty; `TLS_CIPHERS_DEFAULT` will be used
    if (tls_config_set_ciphers(this->m_config.get(), ciphers.data()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

/**
 * Default is "default" = "X25519,P-256,P-384"
 */
void TLSServerContext::set_curves(std::string_view curves)
{
    // `curves` can be empty; `TLS_ECDHE_CURVES` will be used
    if (tls_config_set_ecdhecurves(this->m_config.get(), curves.data()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_session_id(std::span<const unsigned char> session_id)
{
    if (session_id.empty()) [[unlikely]] {
        throw std::invalid_argument("session_id must not be empty");
    }

    if (session_id.size() > TLS_MAX_SESSION_ID_LENGTH) [[unlikely]] {
        throw std::invalid_argument("session_id must not exceed TLS_MAX_SESSION_ID_LENGTH");
    }

    if (tls_config_set_session_id(this->m_config.get(), session_id.data(), session_id.size()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::set_session_lifetime(int lifetime)
{
    if (tls_config_set_session_lifetime(this->m_config.get(), lifetime) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

void TLSServerContext::add_ticket_key(uint32_t keyrev, std::span<unsigned char, TLS_TICKET_KEY_SIZE> key)
{
    if (key.size() != TLS_TICKET_KEY_SIZE) [[unlikely]] {
        throw std::invalid_argument("invalid key size");
    }

    if (tls_config_add_ticket_key(this->m_config.get(), keyrev, key.data(), key.size_bytes()) != 0) {
        throw TLSConfigException(tls_config_error(this->m_config.get()));
    }
}

std::shared_ptr<TLSContext> TLSServerContext::accept(int fd) const
{
    tls* client_ctx = nullptr;
    if (-1 == tls_accept_socket(this->m_context.get(), &client_ctx, fd)) {
        throw TLSAcceptException(tls_error(this->m_context.get()));
    }

    return TLSContext::create(client_ctx, TLSContext::Passkey<TLSServerContext>{});
}

std::string_view TLSServerContext::get_error() const
{
    return tls_error(this->m_context.get());
}

void TLSServerContext::configure()
{
    if (tls_configure(this->m_context.get(), this->m_config.get()) != 0) {
        throw TLSConfigException(tls_error(this->m_context.get()));
    }

    this->m_configured = true;
}

tls* TLSServerContext::get_context()
{
    if (!this->m_configured) {
        this->configure();
    }

    return this->m_context.get();
}

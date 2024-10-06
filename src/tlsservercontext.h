#ifndef A2AA408D_BD14_4F04_9950_DE9B21366C2D
#define A2AA408D_BD14_4F04_9950_DE9B21366C2D

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <tls.h>

#include "export.h"

class TLSContext;

class WWA_TLS_SERVER_HELPERS_EXPORT TLSServerContext : public std::enable_shared_from_this<TLSServerContext> {
private:
    struct PrivateTag {};

public:
    [[nodiscard]] static std::shared_ptr<TLSServerContext> create();

    explicit TLSServerContext(const PrivateTag&);
    TLSServerContext(const TLSServerContext&)            = delete;
    TLSServerContext(TLSServerContext&&)                 = default;
    TLSServerContext& operator=(const TLSServerContext&) = delete;
    TLSServerContext& operator=(TLSServerContext&&)      = default;
    ~TLSServerContext();

    void set_ca_path(std::string_view path);
    void set_ca(std::string_view ca);
    void set_keypair(std::string_view cert, std::string_view key);
    void set_keypair(std::string_view cert, std::string_view key, std::string_view ocsp);
    void set_ocsp_staple(std::string_view ocsp);
    void add_keypair(std::string_view cert, std::string_view key);
    void add_keypair(std::string_view cert, std::string_view key, std::string_view ocsp);
    void set_crl(std::string_view crl);

    void set_ca(std::span<const std::uint8_t> ca);
    void set_keypair(std::span<const std::uint8_t> cert, std::span<const std::uint8_t> key);
    void set_keypair(
        std::span<const std::uint8_t> cert, std::span<const std::uint8_t> key, std::span<const std::uint8_t> ocsp
    );
    void set_ocsp_staple(std::span<const std::uint8_t> ocsp);
    void add_keypair(std::span<const std::uint8_t> cert, std::span<const std::uint8_t> key);
    void add_keypair(
        std::span<const std::uint8_t> cert, std::span<const std::uint8_t> key, std::span<const std::uint8_t> ocsp
    );
    void set_crl(std::span<const std::uint8_t> crl);

    void set_alpn(std::string_view alpn);
    void set_verify_depth(int depth);
    void set_verify_client();
    void set_verify_client_optional();
    void enable_dhe();
    void set_dhe_params(std::string_view params);
    void set_protocols(std::string_view protocols);
    void set_ciphers(std::string_view ciphers);
    void set_curves(std::string_view curves);

    void set_session_id(std::span<const unsigned char> session_id);
    void set_session_lifetime(int lifetime);
    void add_ticket_key(uint32_t keyrev, std::span<unsigned char, TLS_TICKET_KEY_SIZE> key);

    [[nodiscard]] std::shared_ptr<TLSContext> accept(int fd) const;

    [[nodiscard]] std::string_view get_error() const;

    void configure();

    tls* get_context();

private:
    std::unique_ptr<tls, decltype(&tls_free)> m_context{tls_server(), &tls_free};
    std::unique_ptr<tls_config, decltype(&tls_config_free)> m_config{tls_config_new(), &tls_config_free};
    bool m_configured = false;
};

#endif /* A2AA408D_BD14_4F04_9950_DE9B21366C2D */

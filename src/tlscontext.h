#ifndef F6B8153C_6A14_4CE8_BFCA_33BFCE450269
#define F6B8153C_6A14_4CE8_BFCA_33BFCE450269

#include <cstdint>
#include <ctime>
#include <memory>
#include <span>
#include <string_view>
#include <tls.h>

#include "export.h"

class TLSServerContext;

class WWA_TLS_SERVER_HELPERS_EXPORT TLSContext : public std::enable_shared_from_this<TLSContext> {
private:
    struct PrivateTag {};

public:
    template<typename T>
    struct Passkey {
        friend T;
    };

    [[nodiscard, gnu::nonnull(1)]] static std::shared_ptr<TLSContext>
    create(tls* ctx, const Passkey<TLSServerContext>&);

    TLSContext(tls* ctx, const PrivateTag&);

    [[nodiscard]] int handshake();
    [[nodiscard]] ssize_t read(std::span<char> buf);
    [[nodiscard]] ssize_t write(std::span<const char>);
    int close();

    std::string_view get_error() const;

    std::string_view conn_version() const;
    std::string_view conn_cipher() const;
    int cipher_strength() const;
    std::string_view alpn_selected() const;
    std::string_view server_name() const;
    bool peer_cert_provided() const;
    bool peer_cert_contains_name(std::string_view name) const;
    std::string_view peer_cert_subject() const;
    std::string_view peer_cert_issuer() const;
    std::string_view peer_cert_hash() const;
    std::time_t peer_cert_notbefore() const;
    std::time_t peer_cert_notafter() const;
    std::span<const std::uint8_t> peer_cert_chain_pem() const;

private:
    std::unique_ptr<tls, decltype(&tls_free)> m_context;
};

#endif /* F6B8153C_6A14_4CE8_BFCA_33BFCE450269 */

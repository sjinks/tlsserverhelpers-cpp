#include "tlscontext.h"

#include <tls.h>

#include "tlsexception.h"

std::shared_ptr<TLSContext> TLSContext::create(tls* ctx, const Passkey<TLSServerContext>&)
{
    return std::make_shared<TLSContext>(ctx, TLSContext::PrivateTag{});
}

TLSContext::TLSContext(tls* ctx, const PrivateTag&) : m_context(ctx, &tls_free) {}

int TLSContext::handshake()
{
    if (const auto ret = tls_handshake(this->m_context.get()); ret != -1) {
        return ret;
    }

    throw TLSIOException(tls_error(this->m_context.get()));
}

ssize_t TLSContext::read(std::span<char> buf)
{
    if (const auto num = tls_read(this->m_context.get(), buf.data(), buf.size_bytes()); num != -1) {
        return num;
    }

    throw TLSIOException(tls_error(this->m_context.get()));
}

ssize_t TLSContext::write(std::span<const char> buf)
{
    if (const auto num = tls_write(this->m_context.get(), buf.data(), buf.size_bytes()); num != -1) {
        return num;
    }

    throw TLSIOException(tls_error(this->m_context.get()));
}

int TLSContext::close()
{
    return tls_close(this->m_context.get());
}

std::string_view TLSContext::get_error() const
{
    return tls_error(this->m_context.get());
}

std::string_view TLSContext::conn_version() const
{
    const auto* result = tls_conn_version(this->m_context.get());
    return result != nullptr ? result : std::string_view{};
}

std::string_view TLSContext::conn_cipher() const
{
    const auto* result = tls_conn_cipher(this->m_context.get());
    return result != nullptr ? result : std::string_view{};
}

int TLSContext::cipher_strength() const
{
    return tls_conn_cipher_strength(this->m_context.get());
}

std::string_view TLSContext::alpn_selected() const
{
    const auto* result = tls_conn_alpn_selected(this->m_context.get());
    return result != nullptr ? result : std::string_view{};
}

std::string_view TLSContext::server_name() const
{
    const auto* result = tls_conn_servername(this->m_context.get());
    return result != nullptr ? result : std::string_view{};
}

bool TLSContext::peer_cert_provided() const
{
    return tls_peer_cert_provided(this->m_context.get()) == 1;
}

bool TLSContext::peer_cert_contains_name(std::string_view name) const
{
    return tls_peer_cert_contains_name(this->m_context.get(), name.data()) == 1;
}

std::string_view TLSContext::peer_cert_subject() const
{
    const auto* result = tls_peer_cert_subject(this->m_context.get());
    return result != nullptr ? result : std::string_view{};
}

std::string_view TLSContext::peer_cert_issuer() const
{
    const auto* result = tls_peer_cert_issuer(this->m_context.get());
    return result != nullptr ? result : std::string_view{};
}

std::string_view TLSContext::peer_cert_hash() const
{
    const auto* result = tls_peer_cert_hash(this->m_context.get());
    return result != nullptr ? result : std::string_view{};
}

std::time_t TLSContext::peer_cert_notbefore() const
{
    return tls_peer_cert_notbefore(this->m_context.get());
}

std::time_t TLSContext::peer_cert_notafter() const
{
    return tls_peer_cert_notafter(this->m_context.get());
}

std::span<const std::uint8_t> TLSContext::peer_cert_chain_pem() const
{
    std::size_t len = 0;
    if (const auto* result = tls_peer_cert_chain_pem(this->m_context.get(), &len); result != nullptr) {
        return {result, len};
    }

    return {};
}

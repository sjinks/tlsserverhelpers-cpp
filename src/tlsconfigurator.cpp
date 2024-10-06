#include "tlsconfigurator.h"

#include <cstdlib>
#include <string>

#include "tlsservercontext.h"

namespace {

std::string get_env(std::string_view prefix, std::string_view name)
{
    std::string env_name;
    env_name.reserve(prefix.size() + name.size());
    env_name.append(prefix).append(name);

    if (const auto* value = std::getenv(env_name.c_str()); value != nullptr) {  // NOLINT(concurrency-mt-unsafe)
        return value;
    }

    return {};
}

}  // namespace

std::shared_ptr<TLSServerContext> TLSConfigurator::configure(std::string_view env_prefix)
{
    if (get_env(env_prefix, "HTTPS") == "1") {
        auto context = TLSServerContext::create();

        const auto certificate = get_env(env_prefix, "CERTIFICATE");
        const auto key         = get_env(env_prefix, "PRIVATE_KEY");
        if (!certificate.empty() && !key.empty()) {
            context->set_keypair(certificate, key);
        }

        if (const auto capath = get_env(env_prefix, "CA_CERTIFICATE_PATH"); !capath.empty()) {
            context->set_ca_path(capath);
        }

        if (const auto ca = get_env(env_prefix, "CA_CERTIFICATE"); !ca.empty()) {
            context->set_ca(ca);
        }

        if (const auto trusted_certificate = get_env(env_prefix, "TRUSTED_CERTIFICATE"); !trusted_certificate.empty()) {
            context->set_ocsp_staple(trusted_certificate);
        }

        if (const auto crl = get_env(env_prefix, "CRL"); !crl.empty()) {
            context->set_crl(crl);
        }

        if (const auto protocols = get_env(env_prefix, "TLS_PROTOCOLS"); !protocols.empty()) {
            context->set_protocols(protocols);
        }

        if (const auto ciphers = get_env(env_prefix, "TLS_CIPHERS"); !ciphers.empty()) {
            context->set_ciphers(ciphers);
        }

        if (const auto curves = get_env(env_prefix, "TLS_CURVES"); !curves.empty()) {
            context->set_curves(curves);
        }

        if (get_env(env_prefix, "TLS_VERIFY_CLIENT") == "1") {
            context->set_verify_client();
        }
        else if (get_env(env_prefix, "TLS_VERIFY_CLIENT_OPTIONAL") == "1") {
            context->set_verify_client_optional();
        }

        if (get_env(env_prefix, "TLS_ENABLE_DHE") == "1") {
            context->enable_dhe();
        }

        return context;
    }

    return {};
}

#ifndef A2ED91C9_5DC4_495A_8E7D_3388BFD9DB20
#define A2ED91C9_5DC4_495A_8E7D_3388BFD9DB20

#include <memory>
#include <string_view>

#include "export.h"

class TLSServerContext;

class WWA_TLS_SERVER_HELPERS_EXPORT TLSConfigurator {
public:
    [[nodiscard]] static std::shared_ptr<TLSServerContext> configure(std::string_view env_prefix);
};

#endif /* A2ED91C9_5DC4_495A_8E7D_3388BFD9DB20 */

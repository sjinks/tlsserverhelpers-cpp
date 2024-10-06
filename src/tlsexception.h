#ifndef BE09C4E0_7C06_4D7A_886A_07FCAB12222C
#define BE09C4E0_7C06_4D7A_886A_07FCAB12222C

#include <stdexcept>

#include "export.h"

class WWA_TLS_SERVER_HELPERS_EXPORT TLSException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class WWA_TLS_SERVER_HELPERS_EXPORT TLSAcceptException : public TLSException {
public:
    using TLSException::TLSException;
};

class WWA_TLS_SERVER_HELPERS_EXPORT TLSConfigException : public TLSException {
public:
    using TLSException::TLSException;
};

class WWA_TLS_SERVER_HELPERS_EXPORT TLSIOException : public TLSException {
public:
    using TLSException::TLSException;
};

#endif /* BE09C4E0_7C06_4D7A_886A_07FCAB12222C */

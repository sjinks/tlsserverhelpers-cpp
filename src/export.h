#ifndef F2E977DF_218C_40C9_B741_2DBD2A01E7BB
#define F2E977DF_218C_40C9_B741_2DBD2A01E7BB

#ifdef WWA_TLS_SERVER_HELPERS_STATIC_DEFINE
#    define WWA_TLS_SERVER_HELPERS_EXPORT
#    define WWA_TLS_SERVER_HELPERS_NO_EXPORT
#else
#    ifdef wwa_tls_server_helpers_EXPORTS
/* We are building this library; export */
#        if defined _WIN32 || defined __CYGWIN__
#            define WWA_TLS_SERVER_HELPERS_EXPORT __declspec(dllexport)
#            define WWA_TLS_SERVER_HELPERS_NO_EXPORT
#        else
#            define WWA_TLS_SERVER_HELPERS_EXPORT    [[gnu::visibility("default")]]
#            define WWA_TLS_SERVER_HELPERS_NO_EXPORT [[gnu::visibility("hidden")]]
#        endif
#    else
/* We are using this library; import */
#        if defined _WIN32 || defined __CYGWIN__
#            define WWA_TLS_SERVER_HELPERS_EXPORT __declspec(dllimport)
#            define WWA_TLS_SERVER_HELPERS_NO_EXPORT
#        else
#            define WWA_TLS_SERVER_HELPERS_EXPORT    [[gnu::visibility("default")]]
#            define WWA_TLS_SERVER_HELPERS_NO_EXPORT [[gnu::visibility("hidden")]]
#        endif
#    endif
#endif

#endif /* F2E977DF_218C_40C9_B741_2DBD2A01E7BB */

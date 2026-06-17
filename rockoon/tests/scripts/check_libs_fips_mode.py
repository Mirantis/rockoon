#!/usr/bin/env python3
import ctypes
from ctypes.util import find_library
import json

lib = ctypes.CDLL(find_library("gnutls"))
result = {"gnutls": False, "libcrypto": False}
try:
    # https://www.gnutls.org/manual/html_node/Core-TLS-API.html#gnutls_005fglobal_005finit
    # https://www.gnutls.org/manual/html_node/Core-TLS-API.html#gnutls_005ffips140_005fmode_005fenabled
    lib.gnutls_global_init.restype = ctypes.c_int
    lib.gnutls_fips140_mode_enabled.restype = ctypes.c_uint

    if lib.gnutls_global_init() == 0:
        result["gnutls"] = lib.gnutls_fips140_mode_enabled() != 0
        lib.gnutls_global_deinit()
except AttributeError:
    pass

lib = ctypes.CDLL(find_library("crypto"))
try:
    # https://manpages.debian.org/testing/libssl-doc/EVP_default_properties_is_fips_enabled.3ssl.en.html
    lib.EVP_default_properties_is_fips_enabled.restype = ctypes.c_int
    result["libcrypto"] = lib.EVP_default_properties_is_fips_enabled(0) == 1
except AttributeError:
    pass

print(json.dumps(result))

package com.github.jinahya.kisa.aria.util;

import java.security.MessageDigest;

public final class JavaxSecurityMessageDigestConstants {

    public static final String CRYPTO_SERVICE = MessageDigest.class.getSimpleName();

    public static final String ALGORITHM_MD5 = "MD5";

    public static final String ALGORITHM_SHA_1 = "SHA-1";

    // -----------------------------------------------------------------------------------------------------------------
    private JavaxSecurityMessageDigestConstants() {
        throw new AssertionError("instantiation is not allowed");
    }
}

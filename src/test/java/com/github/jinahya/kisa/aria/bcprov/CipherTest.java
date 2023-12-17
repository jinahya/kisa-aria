package com.github.jinahya.kisa.aria.bcprov;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

@Slf4j
class CipherTest
        extends _CipherTest {

    static Stream<String> modes() {
        return Stream.of(
                "NONE",
                "CBC",
                "CCM",
                "CFB", "CFBx",
                "CTR",
                "CTS",
                "ECB",
                "GCM",
                "KW",
                "KWP",
                "OFB", "OFBx",
                "PCBC"
        );
    }

    static Stream<String> paddings() {
        return Stream.of(
                "NoPadding",
                "ISO10126Padding",
                "OAEPPadding",
//                "OAEPWith<digest>And<mgf>Padding",
                "PKCS1Padding",
                "PKCS5Padding",
                "SSL3Padding"
        );
    }

//    private static Stream<Arguments> requiredToBeSupportedTransformationsAnsKeysizss() {
//        return Stream.of(
//                Arguments.arguments("AES/CBC/NoPadding", List.of(128)),
//                Arguments.arguments("AES/CBC/PKCS5Padding", List.of(128)),
//                Arguments.arguments("AES/ECB/NoPadding", List.of(128)),
//                Arguments.arguments("AES/ECB/PKCS5Padding", List.of(128)),
//                Arguments.arguments("AES/GCM/NoPadding", List.of(128)),
//                Arguments.arguments("DESede/CBC/NoPadding", List.of(168)),
//                Arguments.arguments("DESede/CBC/PKCS5Padding", List.of(168)),
//                Arguments.arguments("DESede/ECB/NoPadding", List.of(168)),
//                Arguments.arguments("DESede/ECB/PKCS5Padding", List.of(168)),
//                Arguments.arguments("RSA/ECB/PKCS1Padding", List.of(1024, 2048)),
//                Arguments.arguments("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", List.of(1024)),
//                Arguments.arguments("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", List.of(2048)),
//                Arguments.arguments("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", List.of(1024, 2048))
//        );
//    }

    private static Stream<String> transformations() {
        return modes().flatMap(m -> paddings().map(p -> ALGORITHM + '/' + m + '/' + p));
    }

    @DisplayName("getInstance(transformation")
    @MethodSource({"transformations"})
    @ParameterizedTest
    void __(final String transformation) {
        try {
            final var instance = Cipher.getInstance(transformation);
            log.debug("supported; transformation: {}, provider: {}", transformation, instance.getProvider());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
//            log.warn("unable to get a cipher instance; transformation: {}", transformation, e);
        }
    }
}

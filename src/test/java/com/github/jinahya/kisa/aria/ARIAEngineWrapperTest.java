package com.github.jinahya.kisa.aria;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.ShortBufferException;
import java.security.InvalidKeyException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class ARIAEngineWrapperTest {

    private static IntStream validKeysizeStream() {
        return IntStream.of(
                128,
                192,
                256
        );
    }

    private static IntStream invalidKeysizeStream() {
        return IntStream.of(
                127,
                191,
                193,
                257
        );
    }

    @DisplayName("newInstanceForEncryption(valid-keysize)")
    @MethodSource({"validKeysizeStream"})
    @ParameterizedTest(name = "[{index}] keysize: {0}")
    void newInstanceForEncryption__ValidKeysize(final int keysize) throws InvalidKeyException {
        final var instance = ARIAEngineWrapper.newInstanceForEncryption(new byte[keysize / Byte.SIZE]);
        assertThat(instance).isNotNull();
    }

    @DisplayName("newInstanceForDecryption(valid-keysize)")
    @MethodSource({"validKeysizeStream"})
    @ParameterizedTest(name = "[{index}] keysize: {0}")
    void newInstanceForDecryption__ValidKeysize(final int keysize) throws InvalidKeyException {
        final var instance = ARIAEngineWrapper.newInstanceForDecryption(new byte[keysize / Byte.SIZE]);
        assertThat(instance).isNotNull();
    }

    @Test
    void __() throws InvalidKeyException, ShortBufferException {
        final var key = new byte[ARIAEngineWrapper.BLOCK_BYTES];
        ThreadLocalRandom.current().nextBytes(key);
        final byte[] plain;
        {
            final int length = ThreadLocalRandom.current().nextInt(8) * ARIAEngineWrapper.BLOCK_BYTES;
            plain = new byte[length];
            ThreadLocalRandom.current().nextBytes(plain);
        }
        final byte[] encrypted = new byte[plain.length];
        {
            final var engine = ARIAEngineWrapper.newInstanceForEncryption(key);
            engine.encrypt(plain, 0, encrypted, 0);
        }
        final byte[] decrypted = new byte[encrypted.length];
        {
            final var engine = ARIAEngineWrapper.newInstanceForDecryption(key);
            engine.decrypt(encrypted, 0, decrypted, 0);
        }
        assertThat(decrypted).isEqualTo(plain);
    }
}

package com.github.jinahya.kisa.aria.bcprov;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyGenerator;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
abstract class _CipherTest {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    // -----------------------------------------------------------------------------------------------------------------
    static void acceptTestVectorBlocks(final String name, final Consumer<? super List<String>> consumer)
            throws IOException {
        try (var resource = _CipherTest.class.getResourceAsStream(name)) {
            assertThat(resource).isNotNull();
            try (var reader = new BufferedReader(new InputStreamReader(resource))) {
                final var lines = new ArrayList<String>();
                for (String line; (line = reader.readLine()) != null; ) {
                    if (line.trim().isEmpty()) {
                        consumer.accept(lines);
                        lines.clear();
                        continue;
                    }
                    final var value = line.substring(line.lastIndexOf('=') + 1).trim();
                    lines.add(value);
                }
            }
        }
    }

    static List<List<String>> getTestVectorBlocks(final String name)
            throws IOException {
        final var blocks = new ArrayList<List<String>>();
        acceptTestVectorBlocks(name, b -> {
            blocks.add(new ArrayList<>(b));
        });
        return blocks;
    }

    // -----------------------------------------------------------------------------------------------------------------
    static final String ALGORITHM = "ARIA";

    static final int BLOCK_SIZE = 128;

    static final int BLOCK_BYTES = BLOCK_SIZE / Byte.SIZE;

    // -----------------------------------------------------------------------------------------------------------------
    static IntStream keysizes() {
        return IntStream.of(
                128,
                192,
                256
        );
    }

    static Key generateKey(final int keysize) throws NoSuchAlgorithmException {
        final var generator = KeyGenerator.getInstance(ALGORITHM);
        generator.init(keysize);
        return generator.generateKey();
    }
}

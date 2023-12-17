package com.github.jinahya.kisa.aria.util;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Random;

public final class JavaNioByteBufferUtils {

    public static ByteBuffer randomized(final ByteBuffer buffer, final Random random) {
        Objects.requireNonNull(buffer, "buffer is null");
        Objects.requireNonNull(random, "random is null");
        if (buffer.hasArray()) {
            JavaLangArrayUtils.randomize(
                    buffer.array(),
                    buffer.arrayOffset() + buffer.position(),
                    buffer.remaining(),
                    random
            );
            return buffer;
        }
        final var src = new byte[buffer.remaining()];
        JavaLangArrayUtils.randomize(
                src,
                0,
                src.length,
                random
        );
        for (byte b : src) {
            buffer.put(buffer.position(), b);
        }
        return buffer;
    }

    private JavaNioByteBufferUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}

package com.github.jinahya.kisa.aria.util;

import java.util.Objects;
import java.util.Random;

public final class JavaLangArrayUtils {

    public static byte[] randomize(final byte[] array, final int offset, final int length,
                                   final Random random) {
        Objects.requireNonNull(array, "array is null");
        if (offset < 0) {
            throw new IllegalArgumentException("negative offset: " + offset);
        }
        if (length > array.length - offset) {
            throw new IllegalArgumentException(
                    "length(" + length + ")" +
                    " > " +
                    "array.length(" + array.length + ") - offset(" + offset + ")");
        }
        Objects.requireNonNull(random, "random is null");
        final var limit = offset + length;
        for (int i = offset; i < limit; i++) {
            array[i] = (byte) random.nextInt();
        }
        return array;
    }

    private JavaLangArrayUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}

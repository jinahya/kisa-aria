package com.github.jinahya.kisa.aria.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Objects;

public final class JavaxSecurityMessageDigestUtils {

    public static Provider[] getProviders(final String algorithm) {
        Objects.requireNonNull(algorithm, "algorithm is null");
        return Security.getProviders(JavaxSecurityMessageDigestConstants.CRYPTO_SERVICE + '.' + algorithm);
    }

    // ---------------------------------------------------------------------------------------------
    public static long update(final MessageDigest digest, final InputStream stream,
                              final byte[] buffer)
            throws IOException {
        Objects.requireNonNull(digest, "digest is null");
        Objects.requireNonNull(stream, "stream is null");
        if (Objects.requireNonNull(buffer, "buffer is null").length == 0) {
            throw new IllegalArgumentException(
                    "zero-length buffer: " + Objects.toString(buffer));
        }
        var count = 0L;
        for (int r; (r = stream.read(buffer)) != -1; count += r) {
            digest.update(buffer, 0, r);
        }
        return count;
    }

//    public static long update(final MessageDigest digest, final File file, final byte[] buffer)
//            throws IOException {
//        if (Objects.requireNonNull(buffer, "buffer is null").length == 0) {
//            throw new IllegalArgumentException("zero-length buffer: " + Objects.toString(buffer));
//        }
//        try (var stream = new FileInputStream(file)) {
//            return update(digest, stream, buffer);
//        }
//    }

//    public static byte[] getDigest(final MessageDigest digest, final File file, final byte[] buffer)
//            throws IOException {
//        final var bytes = update(digest, file, buffer);
//        return digest.digest();
//    }

    public static byte[] getDigest(final String algorithm, final File file, final byte[] buffer)
            throws NoSuchAlgorithmException, IOException {
        final var digest = MessageDigest.getInstance(algorithm);
        try (var stream = new FileInputStream(file)) {
            final var bytes = update(digest, stream, buffer);
            return digest.digest();
        }
    }

    // ---------------------------------------------------------------------------------------------
    public static long update(final MessageDigest digest, final ReadableByteChannel channel,
                              final ByteBuffer buffer)
            throws IOException {
        Objects.requireNonNull(digest, "digest is null");
        Objects.requireNonNull(channel, "channel is null");
        if (Objects.requireNonNull(buffer, "buffer is null").capacity() == 0) {
            throw new IllegalArgumentException("zero-capacity buffer: " + buffer);
        }
        var count = 0L;
        for (int r; (r = channel.read(buffer.clear())) != -1; count += r) {
            digest.update(buffer.flip());
        }
        return count;
    }

//    public static long update(final MessageDigest digest, final Path path, final ByteBuffer buffer)
//            throws IOException {
//        Objects.requireNonNull(digest, "digest is null");
//        if (!Files.isRegularFile(Objects.requireNonNull(path, "path is null"))) {
//            throw new IllegalArgumentException("not a regular file: " + path);
//        }
//        if (Objects.requireNonNull(buffer, "buffer is null").capacity() == 0) {
//            throw new IllegalArgumentException("zero-capacity buffer: " + buffer);
//        }
//        try (var channel = FileChannel.open(path)) {
//            return update(digest, channel, buffer);
//        }
//    }

//    public static byte[] getDigest(final MessageDigest digest, final Path path,
//                                   final ByteBuffer buffer)
//            throws IOException {
//        try (var channel = FileChannel.open(path)) {
//            final var bytes = update(digest, channel, buffer);
//        }
//        return digest.digest();
//    }

    public static byte[] getDigest(final String algorithm, final Path path, final ByteBuffer buffer)
            throws NoSuchAlgorithmException, IOException {
        final var digest = MessageDigest.getInstance(algorithm);
        try (var channel = FileChannel.open(path)) {
            final var bytes = update(digest, channel, buffer);
            return digest.digest();
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JavaxSecurityMessageDigestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}

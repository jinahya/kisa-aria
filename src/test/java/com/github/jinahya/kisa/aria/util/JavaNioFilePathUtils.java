package com.github.jinahya.kisa.aria.util;

/*-
 * #%L
 * verbose-hello-world-api
 * %%
 * Copyright (C) 2018 - 2023 Jinahya, Inc.
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Utilities for {@link java.nio.file} package.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@Slf4j
public final class JavaNioFilePathUtils {

    @SuppressWarnings({
            "java:S127"
    })
    public static Path writeRandomBytes(final Path path, int bytes, final ByteBuffer buffer,
                                        long position)
            throws IOException {
        Objects.requireNonNull(path, "path is null");
        if (Objects.requireNonNull(buffer, "buffer is null").capacity() == 0) {
            throw new IllegalArgumentException("zero-capacity buffer: " + buffer);
        }
        if (position < 0L) {
            throw new IllegalArgumentException("negative position: " + position);
        }
        try (var channel = FileChannel.open(path, StandardOpenOption.WRITE)) {
            for (int w; bytes > 0; bytes -= w) {
                JavaNioByteBufferUtils.randomized(buffer.clear(), ThreadLocalRandom.current());
                buffer.limit(Math.min(buffer.limit(), bytes));
                w = channel.write(buffer, position);
                assert w >= 0;
                position += w;
            }
            channel.force(false);
        }
        return path;
    }

    public static Path fillRandom(final Path path, int bytes, long position)
            throws IOException {
        Objects.requireNonNull(path, "path is null");
        if (position < 0L) {
            throw new IllegalArgumentException("negative position: " + position);
        }
        try (var channel = FileChannel.open(path, StandardOpenOption.CREATE,
                                            StandardOpenOption.WRITE)) {
            final var src = ByteBuffer.allocate(128);
            assert src.hasArray();
            src.position(src.limit());
            for (int w; bytes > 0; bytes -= w) {
                if (!src.hasRemaining()) {
                    ThreadLocalRandom.current().nextBytes(src.array());
                    src.clear().limit(Math.min(src.limit(), bytes));
                }
                w = channel.write(src, position);
                assert w >= 0;
                position += w;
            }
            channel.force(false);
        }
        return path;
    }

    private JavaNioFilePathUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}

package com.github.jinahya.kisa.aria.bcprov;

import com.github.jinahya.kisa.aria.util.JavaIoFileUtils;
import com.github.jinahya.kisa.aria.util.JavaNioFilePathUtils;
import com.github.jinahya.kisa.aria.util.JavaxCryptoCipherUtils;
import com.github.jinahya.kisa.aria.util.JavaxSecurityMessageDigestConstants;
import com.github.jinahya.kisa.aria.util.JavaxSecurityMessageDigestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("/CFB/NoPadding")
@Slf4j
class Cipher_CFB_NoPadding_Test
        extends _CipherTest {

    private static final String MODE = "CFB";

    private static final String PADDING = "NoPadding";

    @MethodSource({"keysizes"})
    @ParameterizedTest(name = "[{index}] keysize: {0}")
    void __(final int keysize, @TempDir final File dir)
            throws IOException, NoSuchPaddingException, NoSuchAlgorithmException,
                   InvalidAlgorithmParameterException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {
        // ------------------------------------------------------------------------------------------------------- files
        final var plainFile = File.createTempFile("tmp", "tmp", dir);
        final var encryptedFile = File.createTempFile("tmp", "tmp", dir);
        final var decryptedFile = File.createTempFile("tmp", "tmp", dir);
        // ------------------------------------------------------------------------------------------------------ cipher
        final var transformation = ALGORITHM + '/' + MODE + '/' + PADDING;
        final var cipher = Cipher.getInstance(transformation);
        final var blockSize = cipher.getBlockSize();
        assert blockSize == 128 >> 3;
        // --------------------------------------------------------------------------------------------------------- key
        final var key = generateKey(keysize);
        // ------------------------------------------------------------------------------------------------------ params
        final AlgorithmParameterSpec params;
        {
            final var iv = new byte[blockSize];
            ThreadLocalRandom.current().nextBytes(iv);
            params = new IvParameterSpec(iv);
        }
        // ----------------------------------------------------------------------------------------------------- encrypt
        {
            JavaIoFileUtils.writeRandomBytes(
                    plainFile,
                    false,
                    ThreadLocalRandom.current().nextInt(8192) / blockSize * blockSize,
                    new byte[1024]
            );
            log.debug("plainFile.length: {}", plainFile.length());
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            try (var input = new FileInputStream(plainFile);
                 var output = new FileOutputStream(encryptedFile)) {
                final long bytes = JavaxCryptoCipherUtils.update(
                        cipher,
                        input,
                        new byte[1024],
                        output
                );
                assertThat(bytes).isEqualTo(plainFile.length());
                output.write(cipher.doFinal());
                output.flush();
            }
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
            try (var input = new FileInputStream(encryptedFile);
                 var outputStream = new FileOutputStream(decryptedFile)) {
                final var bytes = JavaxCryptoCipherUtils.update(
                        cipher,
                        input,
                        new byte[1024],
                        outputStream
                );
                assertThat(bytes).isEqualTo(encryptedFile.length());
                outputStream.write(cipher.doFinal());
                outputStream.flush();
            }
            log.debug("decryptedFile.length: {}", decryptedFile.length());
            assertThat(decryptedFile).hasSize(plainFile.length());
        }
        // ------------------------------------------------------------------------------------------------------ verify
        {
            final var messageDigestAlgorithm = JavaxSecurityMessageDigestConstants.ALGORITHM_MD5;
            final var buffer = new byte[1024];
            final var plainFileDigest = JavaxSecurityMessageDigestUtils.getDigest(
                    messageDigestAlgorithm,
                    plainFile,
                    buffer
            );
            log.debug("plainFile.digest: {}", Hex.toHexString(plainFileDigest));
            final var decryptedFileDigest = JavaxSecurityMessageDigestUtils.getDigest(
                    messageDigestAlgorithm,
                    decryptedFile,
                    buffer
            );
            log.debug("decryptedFile.digest: {}", Hex.toHexString(decryptedFileDigest));
            assertThat(decryptedFileDigest).isEqualTo(plainFileDigest);
        }
    }

    @MethodSource({"keysizes"})
    @ParameterizedTest(name = "[{index}] keysize: {0}")
    void __(final int keysize, @TempDir final Path dir)
            throws IOException, NoSuchPaddingException, NoSuchAlgorithmException,
                   InvalidAlgorithmParameterException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {
        // ------------------------------------------------------------------------------------------------------- paths
        final var plainPath = Files.createTempFile(dir, null, null);
        final var encryptedPath = Files.createTempFile(dir, null, null);
        final var decryptedPath = Files.createTempFile(dir, null, null);
        // ------------------------------------------------------------------------------------------------------ cipher
        final var transformation = ALGORITHM + '/' + MODE + '/' + PADDING;
        final var cipher = Cipher.getInstance(transformation);
        final var blockSize = cipher.getBlockSize();
        assert blockSize == BLOCK_BYTES;
        // --------------------------------------------------------------------------------------------------------- key
        final var key = generateKey(keysize);
        // ------------------------------------------------------------------------------------------------------ params
        final AlgorithmParameterSpec params;
        {
            final var iv = new byte[blockSize];
            SecureRandom.getInstanceStrong().nextBytes(iv);
            params = new IvParameterSpec(iv);
        }
        // ----------------------------------------------------------------------------------------------------- encrypt
        {
            JavaNioFilePathUtils.writeRandomBytes(
                    plainPath,
                    ThreadLocalRandom.current().nextInt(8192) / blockSize * blockSize,
                    ByteBuffer.allocate(1024),
                    0L
            );
            log.debug("plainPath.size: {}", Files.size(plainPath));
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            try (var readable = FileChannel.open(plainPath, StandardOpenOption.READ);
                 var writable = FileChannel.open(encryptedPath, StandardOpenOption.WRITE)) {
                final long bytes = JavaxCryptoCipherUtils.update(
                        cipher,
                        readable,
                        ByteBuffer.allocate(1024),
                        writable
                );
                assertThat(bytes).isEqualTo(Files.size(plainPath));
                for (var b = ByteBuffer.wrap(cipher.doFinal()); b.hasRemaining(); ) {
                    final var w = writable.write(b);
                    assert w >= 0;
                }
                writable.force(false);
            }
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
            try (var readable = FileChannel.open(encryptedPath, StandardOpenOption.READ);
                 var writable = FileChannel.open(decryptedPath, StandardOpenOption.WRITE)) {
                final var bytes = JavaxCryptoCipherUtils.update(
                        cipher,
                        readable,
                        ByteBuffer.allocate(1024),
                        writable
                );
                assertThat(bytes).isEqualTo(Files.size(encryptedPath));
                for (final var b = ByteBuffer.wrap(cipher.doFinal()); b.hasRemaining(); ) {
                    final var w = writable.write(b);
                    assert w >= 0;
                }
                writable.force(false);
            }
            log.debug("decryptedPath.size: {}", Files.size(decryptedPath));
            assertThat(decryptedPath).hasSize(Files.size(plainPath));
        }
        // ------------------------------------------------------------------------------------------------------ verify
        {
            final var messageDigestAlgorithm = JavaxSecurityMessageDigestConstants.ALGORITHM_SHA_1;
            final var plainPathDigest = JavaxSecurityMessageDigestUtils.getDigest(
                    messageDigestAlgorithm,
                    plainPath,
                    ByteBuffer.allocate(1024)
            );
            log.debug("plainPath.digest: {}", Hex.toHexString(plainPathDigest));
            final var decryptedPathDigest = JavaxSecurityMessageDigestUtils.getDigest(
                    messageDigestAlgorithm,
                    decryptedPath,
                    ByteBuffer.allocate(1024)
            );
            log.debug("decryptedPath.digest: {}", Hex.toHexString(decryptedPathDigest));
            assertThat(decryptedPathDigest).isEqualTo(plainPathDigest);
        }
    }
}

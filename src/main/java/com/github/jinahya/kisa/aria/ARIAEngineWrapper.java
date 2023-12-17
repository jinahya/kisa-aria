package com.github.jinahya.kisa.aria;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidKeyException;

public class ARIAEngineWrapper {

    private static final String NAME = "kr.re.nsri.aria.ARIAEngine";

    private static final Class<?> CLASS;

    private static final Constructor<?> CONSTRUCTOR;

    private static final Method SET_KEY;

    private static final Method SETUP_ROUND_KEYS;

    private static final Method ENCRYPT;

    private static final Method DECRYPT;

    static {
        try {
            CLASS = Class.forName(NAME);
            try {
                CONSTRUCTOR = CLASS.getConstructor(int.class);
                if (!CONSTRUCTOR.isAccessible()) {
                    CONSTRUCTOR.setAccessible(true);
                }
            } catch (final NoSuchMethodException nsme) {
                throw new ExceptionInInitializerError(nsme);
            }
            try {
                SET_KEY = CLASS.getDeclaredMethod("setKey", byte[].class);
                if (!SET_KEY.isAccessible()) {
                    SET_KEY.setAccessible(true);
                }
            } catch (final NoSuchMethodException nsme) {
                throw new ExceptionInInitializerError("unable to find setKey([B) from " + CLASS);
            }
            try {
                SETUP_ROUND_KEYS = CLASS.getDeclaredMethod("setupRoundKeys");
                if (!SETUP_ROUND_KEYS.isAccessible()) {
                    SETUP_ROUND_KEYS.setAccessible(true);
                }
            } catch (final NoSuchMethodException nsme) {
                throw new ExceptionInInitializerError("unable to find setupRoundKeys() from " + CLASS);
            }
            try {
                ENCRYPT = CLASS.getDeclaredMethod("encrypt", byte[].class, int.class, byte[].class, int.class);
                if (!ENCRYPT.isAccessible()) {
                    ENCRYPT.setAccessible(true);
                }
            } catch (final NoSuchMethodException nsme) {
                throw new ExceptionInInitializerError("unable to find encrypt([B, I, [B, I) from " + CLASS);
            }
            try {
                DECRYPT = CLASS.getDeclaredMethod("decrypt", byte[].class, int.class, byte[].class, int.class);
                if (!DECRYPT.isAccessible()) {
                    DECRYPT.setAccessible(true);
                }
            } catch (final NoSuchMethodException nsme) {
                throw new ExceptionInInitializerError("unable to find decrypt([B, I, [B, I) from " + CLASS);
            }
        } catch (final ClassNotFoundException cnfe) {
            throw new ExceptionInInitializerError(cnfe);
        }
    }

    static final int BLOCK_SIZE = 128;

    static final int BLOCK_BYTES = BLOCK_SIZE / Byte.SIZE;

    // -----------------------------------------------------------------------------------------------------------------
    private static ARIAEngineWrapper newInstance(final int mode, final byte[] key) throws InvalidKeyException {
        if (mode != Cipher.ENCRYPT_MODE && mode != Cipher.DECRYPT_MODE) {
            throw new IllegalArgumentException(
                    "invalid mode: " + mode + ";" +
                    " not Cipher.ENCRYPT_MODE(" + Cipher.ENCRYPT_MODE + ")" +
                    " nor Cipher.DECRYPT_MODE(" + Cipher.DECRYPT_MODE + ")"
            );
        }
        final Object engine;
        try {
            engine = CONSTRUCTOR.newInstance(key.length * Byte.SIZE);
            SET_KEY.invoke(engine, key);
            SETUP_ROUND_KEYS.invoke(engine);
        } catch (final InstantiationException ie) {
            throw new RuntimeException(ie);
        } catch (final IllegalAccessException iae) {
            throw new RuntimeException(iae);
        } catch (final InvocationTargetException ite) {
            final Throwable cause = ite.getCause();
            if (cause instanceof InvalidKeyException) {
                throw (InvalidKeyException) cause;
            }
            throw new RuntimeException(ite);
        }
        if (mode == Cipher.ENCRYPT_MODE) {
            return new ARIAEngineWrapper(engine) {
                @Override
                public int decrypt(final byte[] input, final int inputOffset, final byte[] output,
                                   final int outputOffset)
                        throws ShortBufferException {
                    throw new IllegalStateException("not initialized for decryption");
                }
            };
        }
        assert mode == Cipher.DECRYPT_MODE;
        return new ARIAEngineWrapper(engine) {
            @Override
            public int encrypt(final byte[] input, final int inputOffset, final byte[] output, final int outputOffset)
                    throws ShortBufferException {
                throw new IllegalStateException("not initialized for encryption");
            }
        };
    }

    public static ARIAEngineWrapper newInstanceForEncryption(final byte[] key) throws InvalidKeyException {
        return newInstance(Cipher.ENCRYPT_MODE, key);
    }

    public static ARIAEngineWrapper newInstanceForDecryption(final byte[] key) throws InvalidKeyException {
        return newInstance(Cipher.DECRYPT_MODE, key);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private ARIAEngineWrapper(final Object engine) {
        super();
        if (engine == null) {
            throw new NullPointerException("engine is null");
        }
        this.engine = engine;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public int encrypt(final byte[] input, int inputOffset, final byte[] output, int outputOffset)
            throws ShortBufferException {
        if (input == null) {
            throw new NullPointerException("input is null");
        }
        if (inputOffset < 0) {
            throw new IllegalArgumentException("inputOffset(" + inputOffset + ") is negative");
        }
        if (output == null) {
            throw new NullPointerException("output is null");
        }
        if (outputOffset < 0) {
            throw new IllegalArgumentException("outputOffset(" + outputOffset + ") is negative");
        }
        final int blocks = (input.length - inputOffset) / BLOCK_BYTES;
        if (output.length - outputOffset < blocks * BLOCK_BYTES) {
            throw new ShortBufferException(
                    "output.length(" + output.length + ") - outputOffset(" + outputOffset + ") < " +
                    (blocks * BLOCK_BYTES)
            );
        }
        for (int i = 0; i < blocks; i++) {
            try {
                ENCRYPT.invoke(engine, input, inputOffset, output, outputOffset);
                inputOffset += BLOCK_BYTES;
                outputOffset += BLOCK_BYTES;
            } catch (final IllegalAccessException iae) {
                throw new RuntimeException("unable to encrypt", iae);
            } catch (final InvocationTargetException ite) {
                throw new RuntimeException("unable to encrypt", ite);
            }
        }
        return blocks * BLOCK_BYTES;
    }

    public int decrypt(final byte[] input, int inputOffset, final byte[] output, int outputOffset)
            throws ShortBufferException {
        if (input == null) {
            throw new NullPointerException("input is null");
        }
        if (inputOffset < 0) {
            throw new IllegalArgumentException("inputOffset(" + inputOffset + ") is negative");
        }
        if (output == null) {
            throw new NullPointerException("output is null");
        }
        if (outputOffset < 0) {
            throw new IllegalArgumentException("outputOffset(" + outputOffset + ") is negative");
        }
        final int blocks = (input.length - inputOffset) / BLOCK_BYTES;
        if (output.length - outputOffset < blocks * BLOCK_BYTES) {
            throw new ShortBufferException(
                    "output.length(" + output.length + ") - outputOffset(" + outputOffset + ") < " +
                    (blocks * BLOCK_BYTES)
            );
        }
        for (int i = 0; i < blocks; i++) {
            try {
                DECRYPT.invoke(engine, input, inputOffset, output, outputOffset);
                inputOffset += BLOCK_BYTES;
                outputOffset += BLOCK_BYTES;
            } catch (final IllegalAccessException iae) {
                throw new RuntimeException("unable to decrypt", iae);
            } catch (final InvocationTargetException ite) {
                throw new RuntimeException("unable to decrypt", ite);
            }
        }
        return blocks * BLOCK_BYTES;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private final Object engine;
}

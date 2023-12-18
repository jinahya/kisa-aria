# kisa-aria

A simple proxy for [KISA ARIA](https://seed.kisa.or.kr/kisa/algorithm/EgovAriaInfo.do) cipher.

## kr.re.nsri.aria.ARIAEngine

The source code provided by KISA is, unfortunately, not usable at all. The following signatures are what it has. (Non-private methods are listed.)

```java
class ARIAEngine {

    public ARIAEngine(int keySize)
            throws InvalidKeyException {
    }

    void setKey(byte[] masterKey)
            throws InvalidKeyException {
    }

    void encrypt(byte[] i, int ioffset, byte[] o, int ooffset)
            throws InvalidKeyException {
    }

    byte[] encrypt(byte[] i, int ioffset)
            throws InvalidKeyException {
    }

    void decrypt(byte[] i, int ioffset, byte[] o, int ooffset)
            throws InvalidKeyException {
    }

    byte[] decrypt(byte[] i, int ioffset)
            throws InvalidKeyException {
    }
}
```

## com.github.jinahya.kisa.aria.ARIAEngineProxy

I created a proxy class invokes, using reflection, methods of the `ARIAEngine` class.

(I've never tried to implement [`javax.crypto.Cipher`](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html), and I will never.)

```java
public class ARIAEngineProxy {

    public static ARIAEngineProxy newInstanceForEncryption(final byte[] key)
            throws InvalidKeyException {
    }

    public static ARIAEngineProxy newInstanceForDecryption(final byte[] key)
            throws InvalidKeyException {
    }

    public int encrypt(byte[] input, int inputOffset,
                       byte[] output, int outputOffset)
            throws ShortBufferException {
    }

    public void encrypt(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException {
    }

    public int decrypt(byte[] input, int inputOffset,
                       byte[] output, int outputOffset)
            throws ShortBufferException {
    }

    public void decrypt(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException {
    }
}
```

## Using the [Legion of the Bouncy Castle](https://www.bouncycastle.org/java.html)

This module includes test classes use the [Legion of the Bouncy Castle](https://www.bouncycastle.org/java.html) as a [JCE Provider](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/Provider.html).

Here comes an example uses standard classes for `ARIA` algorithm.

```java

@DisplayName("ARIA/CBC/PKCS5Padding")
class ReadMeTest {

    static {
        Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );
    }

    @ValueSource(ints = {128, 192, 256})
    @ParameterizedTest(name = "[{index}] keysize: {0}")
    void __(final int keysize, @TempDir final File dir) throws Exception {
        final var algorithm = "ARIA";
        final var mode = "CBC";
        final var padding = "PKCS5Padding";
        final var transformation = algorithm + '/' + mode + '/' + padding;
        final var cipher = Cipher.getInstance(transformation);
        final var blockSize = cipher.getBlockSize();
        assert blockSize == 16;
        final Key key;
        {
            final var generator = KeyGenerator.getInstance(algorithm);
            generator.init(keysize);
            key = generator.generateKey();
        }
        final AlgorithmParameterSpec params;
        {
            final var iv = new byte[blockSize];
            ThreadLocalRandom.current().nextBytes(iv);
            params = new IvParameterSpec(iv);
        }
        {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
        }
        {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        }
    }
}
```

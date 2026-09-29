import android.security.keystore.KeyGenParameterSpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;
import javax.crypto.*;

// JVM replacement for AndroidKeyStore: uses real JCE AES/GCM but cannot model
// hardware binding or authentication validity. The prompt is separately faked.
public final class FakeAndroidKeyStore extends Provider {
    static final Map<String,Key> keys = new HashMap<>();
    public FakeAndroidKeyStore() {
        super("AndroidKeyStore", "1", "JVM test keystore");
        put("KeyStore.AndroidKeyStore", Store.class.getName());
        put("KeyGenerator.AES", Generator.class.getName());
    }
    public static final class Generator extends KeyGeneratorSpi {
        private String alias;
        @Override protected void engineInit(java.security.spec.AlgorithmParameterSpec spec, SecureRandom random) {
            KeyGenParameterSpec params=(KeyGenParameterSpec)spec;
            if (!params.auth) throw new AssertionError("wrapping key must require authentication");
            alias=params.alias;
        }
        @Override protected void engineInit(int size,SecureRandom random){throw new AssertionError();}
        @Override protected void engineInit(SecureRandom random){throw new AssertionError();}
        @Override protected SecretKey engineGenerateKey() {
            try { KeyGenerator generator=KeyGenerator.getInstance("AES"); generator.init(256); SecretKey key=generator.generateKey();keys.put(alias,key);return key; }
            catch(Exception e){throw new RuntimeException(e);}
        }
    }
    public static final class Store extends KeyStoreSpi {
        @Override public Key engineGetKey(String alias,char[] password){return keys.get(alias);}
        @Override public Certificate[] engineGetCertificateChain(String a){return null;}
        @Override public Certificate engineGetCertificate(String a){return null;}
        @Override public Date engineGetCreationDate(String a){return null;}
        @Override public void engineSetKeyEntry(String a,Key k,char[] p,Certificate[] c){keys.put(a,k);}
        @Override public void engineSetKeyEntry(String a,byte[] k,Certificate[] c){throw new UnsupportedOperationException();}
        @Override public void engineSetCertificateEntry(String a,Certificate c){throw new UnsupportedOperationException();}
        @Override public void engineDeleteEntry(String a){keys.remove(a);}
        @Override public Enumeration<String> engineAliases(){return Collections.enumeration(keys.keySet());}
        @Override public boolean engineContainsAlias(String a){return keys.containsKey(a);}
        @Override public int engineSize(){return keys.size();}
        @Override public boolean engineIsKeyEntry(String a){return keys.containsKey(a);}
        @Override public boolean engineIsCertificateEntry(String a){return false;}
        @Override public String engineGetCertificateAlias(Certificate c){return null;}
        @Override public void engineStore(OutputStream s,char[] p){}
        @Override public void engineLoad(InputStream s,char[] p){}
    }
}

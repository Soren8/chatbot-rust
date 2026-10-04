import android.content.Context;
import android.content.SharedPreferences;
import android.webkit.CookieManager;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;
import com.chatbot.app.NativeSecureKeyPlugin;
import com.getcapacitor.PluginCall;
import java.security.Security;
import java.util.*;

public final class NativeUnlockGateTest {
    static final String ACCOUNT="alice", REMEMBER="remember-secret", KEY="encryption-secret";
    static final CookieManager jar=CookieManager.getInstance();
    static final class Memory implements SharedPreferences {
        final Map<String,String> values=new HashMap<>();
        public String getString(String k,String fallback){return values.getOrDefault(k,fallback);}
        public Map<String,?> getAll(){return values;}
        public Editor edit(){return new Editor(){
            final Map<String,String> puts=new HashMap<>();final Set<String> removes=new HashSet<>();boolean clear;
            public Editor putString(String k,String v){puts.put(k,v);return this;}
            public Editor remove(String k){removes.add(k);return this;}
            public Editor clear(){clear=true;return this;}
            public void apply(){if(clear)values.clear();removes.forEach(values::remove);values.putAll(puts);}
            public boolean commit(){apply();return true;}
        };}
    }
    static final class TestContext extends Context {
        final Map<String,Memory> stores=new HashMap<>();
        final String origin;
        TestContext(){this("https://fixture.example");}
        TestContext(String origin){this.origin=origin;}
        public String getString(int id){return origin;}
        public SharedPreferences getSharedPreferences(String name,int mode){return stores.computeIfAbsent(name,k->new Memory());}
    }
    static PluginCall call(){PluginCall c=new PluginCall();c.args.put("account",ACCOUNT);return c;}
    static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    static void rejected(PluginCall call,String reason){check(call.rejections==1&&call.resolutions==0,reason+": expected rejection; got "+call.result+" / "+call.error);check(!call.keepAlive,reason+": keepAlive");}
    static void noInjection(PluginCall c,String reason){rejected(c,reason);check(jar.injected.isEmpty()&&jar.flushes==0&&jar.jar.isEmpty(),reason+": jar changed");check(c.result==null,reason+": bridge data leaked");}
    static void resetJar(){jar.jar.clear();jar.injected.clear();jar.flushes=0;}
    public static void main(String[] args) {
        Security.addProvider(new FakeAndroidKeyStore());
        TestContext context=new TestContext();
        NativeSecureKeyPlugin plugin=new NativeSecureKeyPlugin();plugin.context=context;plugin.activity=new FragmentActivity();

        PluginCall missingPassword=new PluginCall();missingPassword.args.put("salt","c2FsdA==");plugin.deriveKeyFromPassword(missingPassword);
        rejected(missingPassword,"password is required");check("password is required".equals(missingPassword.error),"missing password message");
        PluginCall emptyPassword=new PluginCall();emptyPassword.args.put("password","");emptyPassword.args.put("salt","c2FsdA==");plugin.deriveKeyFromPassword(emptyPassword);
        rejected(emptyPassword,"password is required");check("password is required".equals(emptyPassword.error),"empty password message");
        PluginCall missingSalt=new PluginCall();missingSalt.args.put("password","password");plugin.deriveKeyFromPassword(missingSalt);
        rejected(missingSalt,"salt is required");check("salt is required".equals(missingSalt.error),"missing salt message");
        PluginCall emptySalt=new PluginCall();emptySalt.args.put("password","password");emptySalt.args.put("salt","");plugin.deriveKeyFromPassword(emptySalt);
        rejected(emptySalt,"salt is required");check("salt is required".equals(emptySalt.error),"empty salt message");
        PluginCall derived=new PluginCall();derived.args.put("password","password");derived.args.put("salt","c2FsdA==");plugin.deriveKeyFromPassword(derived);
        check(derived.resolutions==1&&derived.rejections==0&&derived.result.get("key") instanceof String&&!((String)derived.result.get("key")).isEmpty(),"password derivation did not resolve key");
        PluginCall missingStoreKey=call();plugin.storeKey(missingStoreKey);
        rejected(missingStoreKey,"key is required");check("key is required".equals(missingStoreKey.error),"missing store key message");
        PluginCall emptyStoreKey=call();emptyStoreKey.args.put("key","");plugin.storeKey(emptyStoreKey);
        rejected(emptyStoreKey,"key is required");check("key is required".equals(emptyStoreKey.error),"empty store key message");
        PluginCall missingSealAccount=new PluginCall();plugin.sealCachedCredentials(missingSealAccount);
        rejected(missingSealAccount,"account is required");check("account is required".equals(missingSealAccount.error),"missing seal account message");
        PluginCall missingUnlockAccount=new PluginCall();plugin.unlockCachedLogin(missingUnlockAccount);
        rejected(missingUnlockAccount,"account is required");check("account is required".equals(missingUnlockAccount.error),"missing unlock account message");

        jar.jar.put("remember-"+ACCOUNT,REMEMBER);jar.jar.put("enc_key-"+ACCOUNT,KEY);
        jar.jar.put("remember",REMEMBER);jar.jar.put("enc_key",KEY);
        jar.jar.put("session","live-session");
        PluginCall seal=call();plugin.sealCachedCredentials(seal);
        check(seal.rejections==0&&Boolean.TRUE.equals(seal.result.get("sealed")),"real seal failed: "+seal.error);
        check(Boolean.FALSE.equals(seal.result.get("cookiesPurged")),"seal must report that the active jar was preserved");
        for(String name:new String[]{"remember-alice","enc_key-alice","remember","enc_key","session"})
            check(jar.jar.containsKey(name),"sealing must preserve active cookie needed for authenticated redirect/request: "+name);
        check(NativeSecureKeyPlugin.hasSealedCredentials(context),"selected origin's sealed credential slot must gate cold entry");
        TestContext otherOrigin=new TestContext("https://other.example");
        check(!NativeSecureKeyPlugin.hasSealedCredentials(otherOrigin),"sealed credential presence must not cross origins");
        check(com.chatbot.app.CredentialCookies.hasCredentialCookie("enc_key-alice=K")
                && !com.chatbot.app.CredentialCookies.hasCredentialCookie("session=S; csrf=C"),"cold cookie gate must distinguish credential bearers");
        plugin.activity=null;
        PluginCall unavailableActivity=call();plugin.unlockCachedLogin(unavailableActivity);
        check(unavailableActivity.rejections==1&&unavailableActivity.resolutions==0&&"activity unavailable".equals(unavailableActivity.error),"activity unavailable result: "+unavailableActivity.error);
        check(!unavailableActivity.keepAlive,"activity unavailable must not keep the rejected call alive");
        plugin.activity=new FragmentActivity();
        PluginCall absentSeal=call();absentSeal.args.put("account","bob");plugin.sealCachedCredentials(absentSeal);
        check(absentSeal.resolutions==1&&absentSeal.rejections==0&&Boolean.FALSE.equals(absentSeal.result.get("sealed")),"missing cached cookies should resolve sealed:false");
        PluginCall noSlot=call();noSlot.args.put("account","bob");plugin.unlockCachedLogin(noSlot);
        check(noSlot.resolutions==1&&noSlot.rejections==0&&Boolean.FALSE.equals(noSlot.result.get("unlocked"))&&"no_credentials".equals(noSlot.result.get("reason")),"missing sealed slot result: "+noSlot.result);
        PluginCall emptySlot=call();emptySlot.args.put("account","");plugin.unlockCachedLogin(emptySlot);
        rejected(emptySlot,"account is required");check("account is required".equals(emptySlot.error),"empty unlock account message");
        Memory prefs=context.stores.get("chatbot_secure_key");
        String dataSlot=prefs.values.keySet().stream().filter(s->s.startsWith("wrapped_creds_data")&&s.endsWith(":"+ACCOUNT)).findFirst().orElseThrow();
        String original=prefs.values.get(dataSlot);
        resetJar();
        // A decrypt before authorization would now fail with the decrypt error.
        prefs.values.put(dataSlot,"invalid-ciphertext");

        BiometricManager.status=1;BiometricPrompt.prompts=0;
        PluginCall unavailable=call();plugin.unlockCachedLogin(unavailable);
        noInjection(unavailable,"unavailable");check(BiometricPrompt.prompts==0,"unavailable prompted");
        check(unavailable.error.equals("biometric or device credential unlock unavailable"),"unavailable error: "+unavailable.error);
        BiometricManager.status=0;BiometricPrompt.mode=1;
        PluginCall cancelled=call();plugin.unlockCachedLogin(cancelled);
        noInjection(cancelled,"cancelled");check(cancelled.error.startsWith("authentication cancelled:"),"cancel error: "+cancelled.error);
        BiometricPrompt.mode=2;
        PluginCall failed=call();plugin.unlockCachedLogin(failed);
        noInjection(failed,"failed then cancelled");check(failed.error.startsWith("authentication cancelled:"),"failed prompt error");
        prefs.values.put(dataSlot,original);

        BiometricPrompt.mode=0;
        jar.jar.put("remember","other-account-token");
        jar.jar.put("enc_key","other-account-key");
        PluginCall success=call();plugin.unlockCachedLogin(success);
        check(success.resolutions==1&&success.rejections==0&&Boolean.TRUE.equals(success.result.get("unlocked")),"unlock failed: "+success.error);
        check(success.result.size()==1&&!success.result.containsKey("key"),"JS bridge leaked key: "+success.result);
        check(!success.keepAlive&&jar.flushes==1&&jar.injected.size()==2,"successful account-scoped cookie injection count");
        for(String name:new String[]{"remember-alice","enc_key-alice"}) {
            String expected=name+"="+(name.startsWith("remember")?REMEMBER:KEY);
            check(jar.jar.get(name).equals(name.startsWith("remember")?REMEMBER:KEY),"missing jar cookie: "+name);
            check(jar.injected.stream().anyMatch(s->s.contains(" "+expected+"; Path=/; SameSite=Strict; HttpOnly")),"missing HttpOnly injection: "+name);
        }
        check("other-account-token".equals(jar.jar.get("remember"))
                && "other-account-key".equals(jar.jar.get("enc_key")),"cached unlock must not overwrite generic cookies attributed to another account");
        jar.jar.put("remember-bob","bob-remember");jar.jar.put("enc_key-bob","bob-key");
        PluginCall bobSeal=call();bobSeal.args.put("account","bob");plugin.sealCachedCredentials(bobSeal);
        check(bobSeal.resolutions==1&&Boolean.TRUE.equals(bobSeal.result.get("sealed")),"second account seal failed");
        jar.jar.put("session","live-session");
        PluginCall purge=call();plugin.purgeCachedCookies(purge);
        check(purge.resolutions==1&&purge.rejections==0&&Boolean.TRUE.equals(purge.result.get("purged")),"login-page credential purge failed: "+purge.error);
        check(jar.jar.containsKey("session")&&jar.jar.keySet().stream().noneMatch(com.chatbot.app.CredentialCookies::isCredentialCookie),"credential purge must retain session and remove all credential cookies");
        check(NativeSecureKeyPlugin.hasSealedCredentials(context),"cookie purge must retain sealed account slots");
        jar.jar.put("enc_key-bob","bob-key");jar.acknowledge=false;
        PluginCall failedPurge=call();plugin.purgeCachedCookies(failedPurge);
        check(failedPurge.rejections==1&&failedPurge.resolutions==0&&"failed to purge cached credentials".equals(failedPurge.error),"purge acknowledgement failure must reject");
        jar.acknowledge=true;
        resetJar();
        byte[] tamperedBytes=java.util.Base64.getDecoder().decode(original);tamperedBytes[tamperedBytes.length-1]^=1;
        prefs.values.put(dataSlot,java.util.Base64.getEncoder().encodeToString(tamperedBytes));
        PluginCall tampered=call();plugin.unlockCachedLogin(tampered);
        noInjection(tampered,"tampered");check(tampered.error.equals("failed to decrypt cached credentials"),"tamper error: "+tampered.error);
        PluginCall clearAlice=call();plugin.clearKey(clearAlice);
        check(clearAlice.resolutions==1&&clearAlice.rejections==0,"account clear failed: "+clearAlice.error);
        PluginCall clearedUnlock=call();plugin.unlockCachedLogin(clearedUnlock);
        check(clearedUnlock.resolutions==1&&Boolean.FALSE.equals(clearedUnlock.result.get("unlocked"))&&"no_credentials".equals(clearedUnlock.result.get("reason")),"cleared account still unlockable: "+clearedUnlock.result);
        check(prefs.values.keySet().stream().anyMatch(k->k.startsWith("wrapped_creds_data")&&k.endsWith(":bob")),"clearKey removed other account slot");
        check(BiometricManager.checks==5&&BiometricPrompt.prompts==4,"prompt path counts");
        System.out.println("validation, no-credentials, clear, and 5 unlock cases passed; real seal + AES/GCM");
    }
}

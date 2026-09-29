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
        public String getString(int id){return "https://fixture.example";}
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
        jar.jar.put("remember-"+ACCOUNT,REMEMBER);jar.jar.put("enc_key-"+ACCOUNT,KEY);
        PluginCall seal=call();plugin.sealCachedCredentials(seal);
        check(seal.rejections==0&&Boolean.TRUE.equals(seal.result.get("sealed")),"real seal failed: "+seal.error);
        Memory prefs=context.stores.get("chatbot_secure_key");
        String dataSlot=prefs.values.keySet().stream().filter(s->s.startsWith("wrapped_creds_data")).findFirst().orElseThrow();
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
        PluginCall success=call();plugin.unlockCachedLogin(success);
        check(success.resolutions==1&&success.rejections==0&&Boolean.TRUE.equals(success.result.get("unlocked")),"unlock failed: "+success.error);
        check(success.result.size()==1&&!success.result.containsKey("key"),"JS bridge leaked key: "+success.result);
        check(!success.keepAlive&&jar.flushes==1&&jar.injected.size()==4,"successful cookie injection count");
        for(String name:new String[]{"remember-alice","remember","enc_key-alice","enc_key"}) {
            String expected=name+"="+(name.startsWith("remember")?REMEMBER:KEY);
            check(jar.jar.get(name).equals(name.startsWith("remember")?REMEMBER:KEY),"missing jar cookie: "+name);
            check(jar.injected.stream().anyMatch(s->s.contains(" "+expected+"; Path=/; SameSite=Strict; HttpOnly")),"missing HttpOnly injection: "+name);
        }
        resetJar();
        byte[] corrupt=java.util.Base64.getDecoder().decode(original);corrupt[corrupt.length-1]^=1;
        prefs.values.put(dataSlot,java.util.Base64.getEncoder().encodeToString(corrupt));
        PluginCall tampered=call();plugin.unlockCachedLogin(tampered);
        noInjection(tampered,"tampered");check(tampered.error.equals("failed to decrypt cached credentials"),"tamper error: "+tampered.error);
        check(BiometricManager.checks==5&&BiometricPrompt.prompts==4,"prompt path counts");
        System.out.println("5 unlock cases passed (unavailable, cancelled, failed, success, tampered); real seal + AES/GCM");
    }
}

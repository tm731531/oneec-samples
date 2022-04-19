package oneec.aes.java.demo;

import com.google.common.base.Charsets;
import com.google.common.base.Strings;
import com.google.common.hash.Hashing;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.util.Base64;

import static org.junit.Assert.assertTrue;

public class TestAES {

    private static Logger log = LoggerFactory.getLogger(TestAES.class);

    String cipherMode = "AES/GCM/NoPadding";

    @Test
    public void testLoadAesKey() throws Exception {

        try{
            String secretKey = "A123456789012345A123456789012345";
            String iv = "B123456789012345";

            String data = "{\"Name\":\"Test\",\"ID\":\"A123456789\"}";

            SecretKeySpec secretKeySpec = AesGcmUtil.getSecretKeySpec(secretKey);
            String secretKeySpecString = Base64.getEncoder().encodeToString(secretKeySpec.getEncoded());

            var keySpec = AesGcmUtil.loadSecretKeySpecFromBase64(secretKeySpecString);

            data = URLEncoder.encode(data, "UTF-8");

            System.out.println("data: "+data);

            var encryptString = AesGcmUtil.encrypt(keySpec, iv, cipherMode, data);

            System.out.println("encryptString: "+encryptString);

            var decryptString = AesGcmUtil.decrypt(keySpec, iv, cipherMode, encryptString);

            System.out.println("decryptString: "+decryptString);
            System.out.println("data: "+data);

            System.out.println(data.equals(decryptString));

            assertTrue("decrypt fail", data.equals(decryptString));

        }catch (Exception e){
            log.error(e.getMessage(), e);
            throw e;
        }
    }

    @Test
    public void testEncryptBody() throws Exception {

        try{
            String secretKey = "A123456789012345A123456789012345";
            String secret_iv = "B123456789012345";

            String data = "{\"Name\":\"Test\",\"ID\":\"A123456789\"}";

            SecretKeySpec secretKeySpec = AesGcmUtil.getSecretKeySpec(secretKey);
            String secretKeySpecString = Base64.getEncoder().encodeToString(secretKeySpec.getEncoded());

            var keySpec = AesGcmUtil.loadSecretKeySpecFromBase64(secretKeySpecString);

            String body = encryptBody(data, keySpec, secret_iv);

            System.out.println("body: "+body);

            String decryptString = decryptBody(body, secretKeySpec, secret_iv);

            System.out.println("decryptString: "+decryptString);
            System.out.println("data: "+data);

            System.out.println(data.equals(decryptString));

            assertTrue("decrypt fail", data.equals(decryptString));

        }catch (Exception e){
            log.error(e.getMessage(), e);
            throw e;
        }
    }

    @Test
    public void testSign() throws Exception {

        try{
            String url = "/oapi/v1/data/merchant/order/RM2111100020966";
            String hash_key = "A123456789012345A123456789012345";

            String body = "vLvmPHmQR5R1HrL9tmv71rHCDlWwRau7CVFuMphe8bmseWfD7+THGrXXnCGx9+AM+g==";

            String sign = sha256HashString(url + body + hash_key);

            System.out.println(sign);

        }catch (Exception e){
            log.error(e.getMessage(), e);
            throw e;
        }
    }

    public String encryptBody(String body, SecretKeySpec secretKeySpec, String secret_iv) throws Exception {
        if(!Strings.isNullOrEmpty(body)){
            String encryptString = AesGcmUtil.encrypt(secretKeySpec, secret_iv, cipherMode, body);
            return encryptString;

        }else{
            return "";
        }
    }

    public String decryptBody(String body, SecretKeySpec secretKeySpec, String secret_iv) throws Exception {
        if(!Strings.isNullOrEmpty(body)){
            String decryptString = AesGcmUtil.decrypt(secretKeySpec, secret_iv, cipherMode, body);

            return decryptString;

        }else{
            return null;
        }
    }

    public String sha256HashString(String str) {
        return Hashing.sha256().hashString(str, Charsets.UTF_8).toString();
    }
}

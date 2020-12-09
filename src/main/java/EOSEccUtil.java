import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.google.bitcoin.core.AddressFormatException;
import com.google.bitcoin.core.Base58;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.math.BigInteger;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;


public class EOSEccUtil {

    public static final String LEGACY_SIG_PREFIX = "EOS";

    public static final String ECC_CURVE_NAME = "secp256k1";

    public static final String SIG_PREFIX = "SIG_K1_";

    public static final String MYKEYMgrContract = "mykeymanager";
    public static final String rpcEndpoint = "https://eos.mykey.tech";

    // MYKEY主网测试账户, mykeydoctest, 第3把操作密钥 EOS6XmD7NK12LnmtXHtdnReTYbgRV1JPeo1M1BQvrHgnz6J1nNCFZ
    // https://bloks.io/account/mykeymanager?loadContract=true&tab=Tables&table=keydata&account=mykeymanager&scope=mykeydoctest&limit=100
    public static final String userAccountAddress = "mykeydoctest";

    // 应用对接登录与签名时用到的是第3个操作密钥
    public static final int signingKeyIndex = 3;

    public static String pubKey;
    public static int status;

    public static void getSigningKeyAndStatus() {
        String url = rpcEndpoint + "/v1/chain/get_table_rows";
        JSONObject payload = new JSONObject();
        payload.put("json", "true");
        payload.put("code", MYKEYMgrContract);
        payload.put("scope", userAccountAddress);
        payload.put("table", "keydata");

        // 1. 获取用户账户的第3个操作密钥
        String res = HttpclientHelper.httpPost(url, payload);

        // 2. 获取用户账户的第3个操作密钥的状态， 正常是0， 冻结是1
        JSONObject signingKeyObj = JSON.parseObject(res).getJSONArray("rows").getJSONObject(signingKeyIndex).getJSONObject("key");
        pubKey = signingKeyObj.getString("pubkey");
        status = signingKeyObj.getIntValue("status");
        System.out.println("pubkey " + pubKey);
        System.out.println("status " + status);
    }

    // 获取待签名数据
    public static String getUnsignedData() {
        // SDK接入方式， 待签名数据需要先组装，不同链的构造格式有差别。参考SDK的"如何验签"章节。
        String unsignedData = "1606900362mykeydocteste9467118-9321-4916-8153-4a5a9087e51emykeyE87E3CC788C44BB8544003AF6CEB62E8";
        return unsignedData;
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // 验证签名
    public static boolean verify(String publKey, String data, String sign) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] digest = sha256.digest(data.getBytes());

        Boolean verified = verifySignature(digest,sign,publKey);
        return verified;
    }

    // 验证签名
    private static boolean verifySignature(byte[] digest, String signature, String publicKeyWif) throws KeyException, AddressFormatException {

        SignatureComponents signatureComponents = checkAndDecodeSignature(signature);

        byte[] xBytes = Base58.decode(publicKeyWif.substring(3));
        xBytes = Arrays.copyOfRange(xBytes, 0, xBytes.length - 4);

        ECNamedCurveParameterSpec paramsSpec = ECNamedCurveTable.getParameterSpec(ECC_CURVE_NAME);
        ECDomainParameters curve = new ECDomainParameters(
                paramsSpec.getCurve(),
                paramsSpec.getG(),
                paramsSpec.getN(),
                paramsSpec.getH());

        boolean verified = false;

        BigInteger r = signatureComponents.r;
        BigInteger s = signatureComponents.s;

        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters params = new ECPublicKeyParameters(curve.getCurve().decodePoint(xBytes), curve);
        signer.init(false, params);
        try {
            verified = signer.verifySignature(digest, r, s);
        } catch (NullPointerException ex) {
            // Bouncy Castle contains a bug that can cause NPEs given specially crafted signatures. Those signatures
            // are inherently invalid/attack sigs so we just fail them here rather than crash the thread.
            throw new KeyException("verify error");
        }

        return verified;
    }

    public static SignatureComponents checkAndDecodeSignature(
            final String signatureString)
            throws KeyException, IllegalArgumentException, AddressFormatException {
        SignatureComponents components = null;

        try {
            // Verify the private key string is properly formatted
            if (!signatureString.startsWith(LEGACY_SIG_PREFIX)
                    && !signatureString.startsWith(SIG_PREFIX)) {
                throw new IllegalArgumentException("Unrecognized Signature format");
            }

            // Check the encoding of the Signature (e.g. EOS/WIF, SIG_K1)
            boolean legacy = signatureString.startsWith(LEGACY_SIG_PREFIX);

            // Remove the prefix
            String trimmedPrivateKeyString;
            if (legacy) {
                trimmedPrivateKeyString = signatureString.replace(LEGACY_SIG_PREFIX, "");
            } else {
                trimmedPrivateKeyString = signatureString.replace(SIG_PREFIX, "");
            }

            // Decode the string and extract its various components (i.e. R, S, i)
            byte[] decodedBytes = Base58.decode(trimmedPrivateKeyString);
            byte i = decodedBytes[0];
            byte[] rBytes = Arrays.copyOfRange(decodedBytes, 1, 33);
            byte[] sBytes = Arrays.copyOfRange(decodedBytes, 33, 65);
            byte[] checksum = Arrays.copyOfRange(decodedBytes, 65, 69);

            // Verify the checksum is correct
            byte[] calculatedChecksum = ripemd160(
                    new byte[]{i},
                    rBytes,
                    sBytes,
                    "K1".getBytes());
            calculatedChecksum = Arrays.copyOfRange(calculatedChecksum, 0, 4);
            if (!Arrays.equals(checksum, calculatedChecksum)) {
                throw new KeyException("Signature Checksum failed");
            }

            // Construct a SignatureComponents object from the components
            components = new SignatureComponents();
            components.r = new BigInteger(1, rBytes);
            components.s = new BigInteger(1, sBytes);
            components.i = i;
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException("Failed to decode Signature", e);
        }

        return components;
    }

    private static byte[] ripemd160(byte[]... inputs) throws NoSuchAlgorithmException {
        byte[] hash = null;

        MessageDigest ripemd160 = MessageDigest.getInstance("RIPEMD160");
        for (byte[] input : inputs) {
            ripemd160.update(input);
        }
        hash = ripemd160.digest();

        return hash;
    }

    /**
     *
     */
    public static class SignatureComponents {
        public BigInteger r;
        public BigInteger s;
        public byte i;

        @Override
        public String toString() {
            return "SignatureComponents{\n" +
                    "    r=" + r + "\n" +
                    "    s=" + s + "\n" +
                    "    i=" + i +
                    '}';
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=========================链上查询签名公钥及状态==================");
        getSigningKeyAndStatus();

        if (EOSEccUtil.status == 1) {
            System.out.println("操作密钥状态不可用");
            return;
        }

        System.out.println("=========================获取待签名数据=========================");
        // unsignedData 和 signature 数据来源于MYKEY主网测试账户， 参考SDK的"如何验签"章节。
        String unsignedData = getUnsignedData();
        String signature = "SIG_K1_KcMxF6rNee2jsM9fge5CZWiENU4j6YLsHgKHD7n9TWvvhLSBtHE8rHV641sVdrw3JRcvCjBtGPRBHSBxzMubzw8DYVnk2e";
        System.out.println("unsignedData " + unsignedData);

        System.out.println("=========================验证签名==============================");
        boolean isTrue = EOSEccUtil.verify(EOSEccUtil.pubKey, unsignedData, signature);
        System.out.println("verify result " + isTrue);
    }
}

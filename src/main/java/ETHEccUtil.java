import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Locale;

public class ETHEccUtil {
    public static final String MYKEYMgrContract = "0xadc92d1fd878580579716d944ef3460e241604b7";
//    public static final String rpcEndpoint = "https://node1.web3api.com";
    public static final String rpcEndpoint = "https://eth.mykey.tech";

    // MYKEY主网测试账户， 0x3bB9E1783D5F60927eD6c3d0c32BfAD055A1b72f， 第3把操作密钥 0x37ac6c8229788643d62eF447eD988Ee7F00f8875
    // https://etherscan.io/address/0xADc92d1fD878580579716d944eF3460E241604b7?#readContract
    public static final String userAccountAddress = "0x3bB9E1783D5F60927eD6c3d0c32BfAD055A1b72f";

    // 应用对接登录与签名时用到的是第3个操作密钥
    public static final int signingKeyIndex = 3;

    public static String pubKey;
    public static String status;

    public static String removeHexPrefix(String hexStr) {
        return hexStr.replaceFirst("0x", "");
    }

    public static void getSigningKeyAndStatus() {
        String url = rpcEndpoint;
        JSONObject payload = new JSONObject();
        payload.put("jsonrpc", "2.0");
        payload.put("id", 1);
        payload.put("method", "eth_call");

        JSONObject trandata = new JSONObject();
        trandata.put("from", "0x0000000000000000000000000000000000000000");
        trandata.put("data", "0x8d431198000000000000000000000000" + removeHexPrefix(userAccountAddress) + "000000000000000000000000000000000000000000000000000000000000000" + signingKeyIndex);
        trandata.put("to", MYKEYMgrContract);

        JSONArray arr = new JSONArray();
        arr.add(trandata);
        arr.add("latest");

        payload.put("params", arr);

        Header[] headers = new Header[3];
        headers[0] = new BasicHeader("Origin", "https://etherscan.io");
        headers[1] = new BasicHeader("Referer", "https://etherscan.io/");
        headers[2] = new BasicHeader("Content-Type", "application/json");

        // 1. 获取用户账户的第3个操作密钥
        String res = HttpclientHelper.httpPost(url, payload, headers);
        pubKey = JSON.parseObject(res).getString("result").replace("000000000000000000000000", "");
//        System.out.println("pubkey " + pubKey);

        // 2. 获取用户账户的第3个操作密钥的状态， 正常是0， 冻结是1
        trandata.put("data", "0x43090116000000000000000000000000" + removeHexPrefix(userAccountAddress) + "000000000000000000000000000000000000000000000000000000000000000" + signingKeyIndex);
        res = HttpclientHelper.httpPost(url, payload, headers);
        status = JSON.parseObject(res).getString("result");
//        System.out.println("status " + status);
    }

    // 获取待签名数据
    public static String getUnsignedData() {
        // SDK接入方式， 待签名数据需要先组装，不同链的构造格式有差别。参考SDK的"如何验签"章节。
        String unsignedData = "3136303639303436383230783362423945313738334435463630393237654436633364306333324266414430353541316237326665393436373131382d393332312d343931362d383135332d3461356139303837653531656d796b65794538374533434337383843343442423835343430303341463643454236324538";
        return unsignedData;
    }

    public static byte[] signPrefixedMessage(byte[] data, String privateKey) {
        BigInteger priKeyBI = Numeric.toBigInt(privateKey);
        ECKeyPair pair = ECKeyPair.create(priKeyBI);
        SignatureData signatureData = Sign.signPrefixedMessage(data, pair);
        ByteBuffer buf = ByteBuffer.allocate(signatureData.getR().length + signatureData.getS().length + signatureData.getV().length);
        buf.put(signatureData.getR());
        buf.put(signatureData.getS());
        buf.put(signatureData.getV());
        return buf.array();
    }

    public static byte[] sign(byte[] data, String privateKey) {
        BigInteger priKeyBI = Numeric.toBigInt(privateKey);
        ECKeyPair pair = ECKeyPair.create(priKeyBI);
        SignatureData signatureData = Sign.signMessage(data, pair);
        ByteBuffer buf = ByteBuffer.allocate(signatureData.getR().length + signatureData.getS().length + signatureData.getV().length);
        buf.put(signatureData.getR());
        buf.put(signatureData.getS());
        buf.put(signatureData.getV());
        return buf.array();
    }

    public static boolean verify(byte[] data, byte[] sig, String pubKey) throws SignatureException {
        byte[] messageHash = Hash.sha3(data);
        byte[] r = Arrays.copyOfRange(sig, 0, 32);
        byte[] s = Arrays.copyOfRange(sig, 32, 64);
        byte[] v = Arrays.copyOfRange(sig, 64, sig.length);
        SignatureData signatureData = new SignatureData(v, r, s);
        BigInteger recoveredPubKey = Sign.signedMessageHashToKey(messageHash, signatureData);
        return recoveredPubKey.equals(Numeric.toBigInt(pubKey));
    }

    public static boolean verifyPrefixedMessage(byte[] data, byte[] sig, String pubKeyAddress) throws SignatureException {
        byte[] r = Arrays.copyOfRange(sig, 0, 32);
        byte[] s = Arrays.copyOfRange(sig, 32, 64);
        byte[] v = Arrays.copyOfRange(sig, 64, sig.length);
        SignatureData signatureData = new SignatureData(v, r, s);
        BigInteger recoveredPubKey = Sign.signedPrefixedMessageToKey(data, signatureData);
        return pubKeyAddress.equals(Keys.getAddress(recoveredPubKey));
    }

    private final static String mHexStr = "0123456789ABCDEF";
    public static String hexStr2Str(String hexStr){
        hexStr = hexStr.toString().trim().replace(" ", "").toUpperCase(Locale.US);
        char[] hexs = hexStr.toCharArray();
        byte[] bytes = new byte[hexStr.length() / 2];
        int iTmp = 0x00;;

        for (int i = 0; i < bytes.length; i++){
            iTmp = mHexStr.indexOf(hexs[2 * i]) << 4;
            iTmp |= mHexStr.indexOf(hexs[2 * i + 1]);
            bytes[i] = (byte) (iTmp & 0xFF);
        }
        return new String(bytes);
    }



    public static void main(String[] args) throws SignatureException {
//        String ud = "3136303639303436383230783362423945313738334435463630393237654436633364306333324266414430353541316237326665393436373131382d393332312d343931362d383135332d3461356139303837653531656d796b65794538374533434337383843343442423835343430303341463643454236324538";
//        System.out.println(hexStr2Str(ud));

        System.out.println("=========================链上查询签名公钥及状态==================");
        getSigningKeyAndStatus();

        if (status.equals("0x0000000000000000000000000000000000000000000000000000000000000001")) {
            System.out.println("操作密钥状态不可用");
            return;
        }

        System.out.println("==========================获取待签名数据========================");
        String unsignedData = hexStr2Str(getUnsignedData());

        String signatureStr = "0x53d86f27d725d3660f242cf0efc1f62aed8c805a39bf9783e2e7c1f65a81d94f775dbcb2e7268672dccbb68518bf5b9ba5f0ad5b2bf20ff4f8c9043f7c43d6651c";
        byte[] signature = Numeric.hexStringToByteArray(signatureStr);

        System.out.println("==============================验证签名=========================");
        boolean isTrue = ETHEccUtil.verifyPrefixedMessage(Hash.sha3(unsignedData.getBytes()), signature, Numeric.cleanHexPrefix(ETHEccUtil.pubKey).toLowerCase());
        System.out.println("verify sig " + isTrue);

    }
}


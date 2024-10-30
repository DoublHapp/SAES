import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BruteForceSAES {
    /**
     * 使用给定的明密文对进行暴力破解SAES密钥
     */
    public static List<Long> crackKeys(String plainText, String cipherText) {
        List<Long> possibleKeys = new ArrayList<>();

        // 从0到65535（0xFFFF），符合16位所有可能值
        for (long key = 0; key <= 0xFFFF; key++) {
            String encryptedText = SAES.Encrypt(plainText, key);

            if (encryptedText.equals(cipherText)) {
                possibleKeys.add(key);
            }
        }

        return possibleKeys;
    }


    /**
     * 使用给定的明密文对进行相遇攻击破解SAES密钥
     */


    public static List<Long> meetInTheMiddle(String plaintext, String ciphertext) {
        List<Long> possibleKeys = new ArrayList<>();
        long key1, key2;
        long maxKeySize = 65536; // 密钥空间为 16 位，所以总共有 2^16 = 65536 种密钥可能

        Map<String, Long> firstHalfEncryption = new HashMap<>();

        // 第一步，对于所有可能的 key1, 加密 plaintext
        for (key1 = 0; key1 < maxKeySize; key1++) {
            String midText = SAES.Encrypt(plaintext, key1);
            firstHalfEncryption.put(midText, key1);
        }

        // 第二步，对于所有可能的 key2, 解密 ciphertext，然后查看是否存在匹配的中间状态
        for (key2 = 0; key2 < maxKeySize; key2++) {
            String decryptedMidText = SAES.Decrypt(ciphertext, key2);
            if (firstHalfEncryption.containsKey(decryptedMidText)) {
                // 找到相匹配的 midText，返回对应的 key1 与 key2 组合
                key1 = firstHalfEncryption.get(decryptedMidText);
                possibleKeys.add((key1 << 16) | key2);// 组合 key1 和 key2 为一个单一的 32 位密钥
            }
        }

        return possibleKeys;
    }
}

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

        Map<String, List<Long>> firstHalfEncryption = new HashMap<>();

        // 第一步，对于所有可能的 key1, 加密 plaintext
        for (key1 = 0; key1 < maxKeySize; key1++) {
            String midText = SAES.Encrypt(plaintext, key1);
            firstHalfEncryption.computeIfAbsent(midText, k -> new ArrayList<>()).add(key1);
        }

        // 第二步，对于所有可能的 key2, 解密 ciphertext，然后查看是否存在匹配的中间状态
        for (key2 = 0; key2 < maxKeySize; key2++) {
            String decryptedMidText = SAES.Decrypt(ciphertext, key2);
            if (firstHalfEncryption.containsKey(decryptedMidText)) {
                List<Long> keys1 = firstHalfEncryption.get(decryptedMidText);
                for (Long k1 : keys1) {
                    possibleKeys.add((k1 << 16) | key2); // 组合 key1 和 key2 为一个单一的 32 位密钥
                }
            }
        }

        return possibleKeys;
    }

    public static void main(String[] args) {
        // 假设已知的明文和密文
        String knownPlainText = "ABCD"; // 二进制表示的16位明文
        String knownCipherText = "{=2õ"; // 二进制表示的16位密文（假设值）

        // 破解密钥
        List<Long> keys = crackKeys(knownPlainText, knownCipherText);

        // 输出所有找到的密钥
        if (!keys.isEmpty()) {
            System.out.println("找到可能的密钥:");
            for (long key : keys) {
                System.out.printf("%04X\n", key); // 输出为16进制格式
            }
        } else {
            System.out.println("未找到任何可行的密钥。");
        }


        String plaintext = "ABCDEF";
        long Key = 0x2D55AC34;
        String ciphertext = SAES.DoubleEncrypt(plaintext, Key);
        System.out.println("明文"+plaintext+"双重加密后得到: "+ciphertext);

        List<Long> k = meetInTheMiddle(plaintext, ciphertext);
        // 输出所有找到的密钥
        if (!k.isEmpty()) {
            System.out.println("找到可能的密钥:");
            for (long key : k) {
                System.out.printf("%04X\n", key); // 输出为16进制格式
            }
        } else {
            System.out.println("未找到任何可行的密钥。");
        }
    }
}

//处理16的整数倍bit流


public class CBC {
    public static final int BLOCK_SIZE = 16; // 16位的块大小

    // 分组加密
    public static String Encrypt(String plaintext, long key, long iv) {
        StringBuilder ciphertext = new StringBuilder();
        long previousBlock = iv; // 初始向量用作第一个previousBlock

        for (int i = 0; i < plaintext.length(); i += BLOCK_SIZE) {
            String Block = plaintext.substring(i, i + BLOCK_SIZE);
            long block = Long.parseLong(Block, 2);

            // XOR操作后加密
            long xorResult = previousBlock ^ block;
            long encryptedBlock = SAES.encrypt(xorResult, key);

            // 更新上一个密文块
            previousBlock = encryptedBlock;

            // 添加到密文字符串
            String encrypted = String.format("%16s", Long.toBinaryString(encryptedBlock)).replace(' ', '0');
            ciphertext.append(encrypted);
        }

        return ciphertext.toString();
    }

    // 分组解密
    public static String Decrypt(String ciphertext, long key, long iv) {
        StringBuilder plaintext = new StringBuilder();
        long previousBlock = iv; // 初始向量用作第一个previousBlock

        for (int i = 0; i < ciphertext.length(); i += BLOCK_SIZE) {
            String binaryBlock = ciphertext.substring(i, i + BLOCK_SIZE);
            long block = Long.parseLong(binaryBlock, 2);

            // 解密后进行XOR操作
            long decryptedBlock = SAES.decrypt(block, key);
            long plaintextBlock = previousBlock ^ decryptedBlock;

            // 更新上一个密文块
            previousBlock = block;

            // 添加到明文字符串
            String plain = String.format("%16s", Long.toBinaryString(plaintextBlock)).replace(' ', '0');
            plaintext.append(plain);
        }

        return plaintext.toString();
    }
}

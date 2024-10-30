public class SAES {

    // S盒
    private static final int[] S_BOX = {
            0x9, 0x4, 0xA, 0xB,
            0xD, 0x1, 0x8, 0x5,
            0x6, 0x2, 0x0, 0x3,
            0xC, 0xE, 0xF, 0x7
    };

    // S盒逆变换
    private static final int[] S_BOX_INV = {
            0xA, 0x5, 0x9, 0xB,
            0x1, 0x7, 0x8, 0xF,
            0x6, 0x0, 0x2, 0x3,
            0xC, 0x4, 0xD, 0xE
    };

    // GF(2^4)下的乘法
    private static long multiply(long a, long b) {
        long product = 0;
        while (b > 0) {
            if ((b & 1) != 0) {
                product ^= a;  // XOR
            }
            a <<= 1;
            if ((a & 0x10) != 0) {
                a ^= 0x13; // 模 x^4 + x + 1 的多项式
            }
            b >>= 1;
        }
        return product & 0xF;
    }

    // 密钥扩展
    public static long[] keyExpansion(long key) {
        long[] roundKeys = new long[3]; // 生成3个16位的轮密钥
        long[] words = new long[6];     // 生成6个8位的中间单词

        words[0] = (key >> 8) & 0xFF;
        words[1] = key & 0xFF;

        // 扩展 w2, w3


        long temp = ((S_BOX[(int)(words[1]&0xF)]<< 4) | S_BOX[(int)(words[1]>>4) & 0xF]) ^ 0x80;
        words[2] = (words[0] ^ temp)& 0xFF; // w2;
        words[3] = (words[1] ^ words[2])& 0xFF; // w3;

        // 扩展 w4, w5
        temp = ((S_BOX[(int)(words[3]&0xF)]<< 4) | S_BOX[(int)(words[3]>>4) & 0xF]) ^ 0x30;
        words[4] = (words[2] ^ temp)& 0xFF; // w4;
        words[5] = (words[4] ^ words[3])& 0xFF; // w5;



        // 生成轮密钥
        for (int i = 0; i < 3; i++) {
            roundKeys[i] = (words[2*i] << 8) | words[2*i + 1];
        }

        return roundKeys;
    }

    // SubBytes
    public static long subBytes(long state) {
        long result = 0;

        result |= (S_BOX[(int)((state >> 12) & 0xF)] << 12); // 处理最高的4位
        result |= (S_BOX[(int)((state >> 8) & 0xF)] << 8);   // 处理次高的4位
        result |= (S_BOX[(int)((state >> 4) & 0xF)] << 4);   // 处理次低的4位
        result |= S_BOX[(int)(state & 0xF)];                 // 处理最低的4位
        return result;
    }

    // InvSubBytes
    public static long invSubBytes(long state) {

        long result = 0;

        result |= (S_BOX_INV[(int)((state >> 12) & 0xF)] << 12); // 处理最高的4位
        result |= (S_BOX_INV[(int)((state >> 8) & 0xF)] << 8);   // 处理次高的4位
        result |= (S_BOX_INV[(int)((state >> 4) & 0xF)] << 4);   // 处理次低的4位
        result |= S_BOX_INV[(int)(state & 0xF)];                 // 处理最低的4位
        return result;
    }

    // ShiftRows
    public static long shiftRows(long state) {
        // 0x1234 → 0x1432，移动类似这样调整的方式
        long temp = state;
        long highNibble = (temp >> 12) & 0xF; // 最高四位
        long midHighNibble = (temp >> 8) & 0xF; // 次高四位
        long midLowNibble = (temp >> 4) & 0xF; // 次低四位
        long lowNibble = temp & 0xF; // 最低四位


        return (highNibble << 12) | (lowNibble << 8) | (midLowNibble << 4) | midHighNibble;

    }

    // AddRoundKey
    public static long addRoundKey(long state, long key) {
        return state ^ key;
    }

    // MixColumns
    public static long mixColumns(long state) {
        long[] s = new long[] {
                (state >> 12) & 0xF, (state >> 8) & 0xF,
                (state >> 4) & 0xF, state & 0xF
        };
        long temp_1 =multiply(s[1],0x4)^s[0];
        long temp_2 =multiply(s[0],0x4)^s[1];
        long temp_3 =multiply(s[3],0x4)^s[2];
        long temp_4 =multiply(s[2],0x4)^s[3];

        return (temp_1 << 12) | (temp_2 << 8) | (temp_3 << 4) | temp_4;
    }


    // 逆MixColumns步骤
    public static long invMixColumns(long state) {
        long[] s = {
                (state >> 12) & 0xF,(state >> 8) & 0xF,
                (state >> 4) & 0xF, state & 0xF
        };
        long temp_1 =multiply(s[0],0x9)^multiply(s[1],0x2);
        long temp_2 =multiply(s[0],0x2)^multiply(s[1],0x9);
        long temp_3 =multiply(s[2],0x9)^multiply(s[3],0x2);
        long temp_4 =multiply(s[2],0x2)^multiply(s[3],0x9);

        return (temp_1 << 12) | (temp_2 << 8) | (temp_3 << 4) | temp_4;
    }

    // 加密和解密的具体实现
    public static long encrypt(long plaintext, long key) {
        long[] keys = keyExpansion(key);
        long state = addRoundKey(plaintext, keys[0]);

        state = subBytes(state);
        state = shiftRows(state);
        state = mixColumns(state);
        state = addRoundKey(state, keys[1]);
        state = subBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state, keys[2]);
        return state;
    }

    // 解密过程
    public static long decrypt(long ciphertext, long key) {
        long[] roundKeys = keyExpansion(key);
        long state = addRoundKey(ciphertext, roundKeys[2]);
        state = shiftRows(state);
        state = invSubBytes(state);

        state = addRoundKey(state, roundKeys[1]);

        state = invMixColumns(state);
        state = shiftRows(state);
        state = invSubBytes(state);
        state = addRoundKey(state, roundKeys[0]);

        return state;
    }

    // 双重加密
    public static String DoubleEncrypt(String plaintext, long key) {
        long k1 = (key >> 16)& 0xFFFF; // 密钥的前16位
        long k2 = key & 0xFFFF; // 密钥的后16位

        String encryptedOnce = Encrypt(plaintext, k1);
        String encryptedTwice = Encrypt(encryptedOnce, k2);

        return encryptedTwice;
    }

    // 双重解密
    public static String  DoubleDecrypt(String ciphertext, long key) {
        long k1 = (key >> 16)& 0xFFFF; // 密钥的前16位
        long k2 = key & 0xFFFF; // 密钥的后16位

        String decryptedOnce = Decrypt(ciphertext, k2);
        String decryptedTwice = Decrypt(decryptedOnce, k1);

        return decryptedTwice;
    }



    // 三重加密
    public static String TripleEncrypt(String plaintext, long key) {
        long k1 = (key >> 32)&0xFFFF;// 密钥的前16位
        long k2 = (key >> 16)&0xFFFF; // 密钥的中间16位
        long k3 = key & 0xFFFF; // 密钥的后16位

        String encryptedOnce = Encrypt(plaintext, k1);
        String encryptedTwice = Encrypt(encryptedOnce, k2);
        String encryptedThrice = Encrypt(encryptedTwice, k3);

        return encryptedThrice;
    }

    // 三重解密
    public static String  TripleDecrypt(String ciphertext, long key) {
        long k1 = (key >> 32)&0xFFFF;// 密钥的前16位
        long k2 = (key >> 16)&0xFFFF; // 密钥的中间16位
        long k3 = key & 0xFFFF; // 密钥的后16位


        String decryptedOnce = Decrypt(ciphertext, k3);
        String decryptedTwice = Decrypt(decryptedOnce, k2);
        String decryptedThrice = Decrypt(decryptedTwice, k1);

        return decryptedThrice;
    }

    //最终实现的加密函数,根据不同输入进行不同的加密操作
    public static String Encrypt(String input, long key) {
        if (isBinaryString(input) && input.length() % 16 == 0) {
            return encryptInputBinary(input, key);
        } else {
            return encryptInputAscii(input, key);
        }
    }
    //最终实现的解密函数,根据不同输入进行不同的解密操作
    public static String Decrypt(String input, long key) {
        if (isBinaryString(input) && input.length() % 16 == 0) {
            return decryptInputBinary(input, key);
        }else {
            return decryptInputAscii(input, key);
        }
    }

    //判断函数
    private static boolean isBinaryString(String input) {
        return input.matches("[01]+");
    }

    /**
     * 使用给定的密钥加密任意长度（必须是16倍数）的二进制字符串。
     */
    public static String encryptInputBinary(String binaryInput, long key) {
        if (binaryInput.length() % 16 != 0) {
            return "Invalid input. Length must be a multiple of 16 bits.";
        }

        StringBuilder encryptedResult = new StringBuilder();

        for (int i = 0; i < binaryInput.length(); i += 16) {
            String substring = binaryInput.substring(i, i + 16);
            String encryptedPart = encryptBinary(substring, key);
            encryptedResult.append(encryptedPart);
        }

        return encryptedResult.toString();
    }

    /**
     * 使用给定的密钥解密任意长度（必须是16倍数）的二进制字符串。
     */
    public static String decryptInputBinary(String binaryInput, long key) {
        if (binaryInput.length() % 16 != 0) {
            return "Invalid input. Length must be a multiple of 16 bits.";
        }

        StringBuilder decryptedResult = new StringBuilder();

        for (int i = 0; i < binaryInput.length(); i += 16) {
            String substring = binaryInput.substring(i, i + 16);
            String decryptedPart = decryptBinary(substring, key);
            decryptedResult.append(decryptedPart);
        }

        return decryptedResult.toString();
    }


    /**
     * 使用给定的密钥加密16位二进制字符串。
     */
    public static String encryptBinary(String binaryInput, long key) {
        if (binaryInput.length() != 16) {
            return "Invalid input. Must be exactly 16 bits.";
        }
        long inputState = Long.parseLong(binaryInput, 2);

        long encryptedState = encrypt(inputState, key);
        return String.format("%16s", Long.toBinaryString(encryptedState)).replace(' ', '0');
    }

    /**
     * 使用给定的密钥解密16位二进制字符串。
     */
    public static String decryptBinary(String binaryInput, long key) {
        if (binaryInput.length() != 16) {
            return "Invalid input. Must be exactly 16 bits.";
        }
        long inputState = Long.parseLong(binaryInput, 2);
        long decryptedState = decrypt(inputState, key);
        return String.format("%16s", Long.toBinaryString(decryptedState)).replace(' ', '0');
    }

    /**
     * 使用给定的密钥加密输入的 ASCII 字符串。
     */
    public static String encryptInputAscii(String plainText, long key) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < plainText.length(); i += 2) {
            long combinedChars = (plainText.charAt(i) << 8) | (i + 1 < plainText.length() ? plainText.charAt(i + 1) : 0);
            long encrypted = encrypt(combinedChars, key);
            result.append((char) (encrypted >> 8)).append((char) (encrypted & 0xFF));
        }
        return result.toString();
    }

    /**
     * 使用给定的密钥解密输入的 ASCII 字符串。
     */
    public static String decryptInputAscii(String cipherText, long key) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < cipherText.length(); i += 2) {
            long combinedChars = (cipherText.charAt(i) << 8) | (cipherText.charAt(i + 1));
            long decrypted = decrypt(combinedChars, key);
            result.append((char) (decrypted >> 8)).append((char) (decrypted & 0xFF));
        }
        return result.toString();
    }

    /**
     * 使用给定的密钥加密2个ASCII字符。
     */
    public static String encryptCharacter(char char1, char char2, long key) {
        long combinedChars = (char1 << 8) | char2;
        long encrypted = encrypt(combinedChars, key);
        return String.valueOf((char) (encrypted >> 8)) + (char) (encrypted & 0xFF);
    }

    /**
     * 使用给定的密钥解密2个ASCII字符。
     */
    public static String decryptCharacter(char char1, char char2, long key) {
        long combinedChars = (char1 << 8) | char2;
        long decrypted = decrypt(combinedChars, key);
        return String.valueOf((char) (decrypted >> 8)) + (char) (decrypted & 0xFF);
    }

    public static void main(String[] args) {
        // 16位明文和密钥
        long plaintext = 0xAC42;
        long temp_666 = 0x2233;
        long temp_667 = 0x3456;
        long zzz= encrypt(temp_666,temp_667);

        System.out.println("ZZZ: "+zzz);

        long key = 0x2D55;

        long temp = 0x8A1C;
        long result_1 = subBytes(temp);
        long result_2 = shiftRows(temp);

        long temp_1 = 0X6C40;
        long result_3 = mixColumns(temp_1);

        long temp_3 =0xA749;
        long result_4 = addRoundKey(temp_3,key);



        System.out.printf("半字节替换: %04X\n", result_1);
        System.out.printf("行移位: %04X\n", result_2);
        System.out.printf("列混淆 : %04X\n", result_3);
        System.out.printf("轮密钥加 : %04X\n", result_4);



        // 加密
        long ciphertext = encrypt(plaintext, key);
        System.out.printf("加密后的密文: %04X\n", ciphertext);

        // 解密
        long decryptedText = decrypt(ciphertext, key);
        System.out.printf("解密后的明文: %04X\n", decryptedText);


        //测试接口
        String str_1 = "1010101010101010";
        String str_2 = "10101010101010101010101010101010";
        String str_3 = "AB";
        String str_4 = "ABCD";

        String res_1 = encryptInputBinary(str_1, key);
        System.out.println("明文1010101010101010加密得到: "+res_1);
        String res_2 = decryptInputBinary(res_1, key);
        System.out.println("密文"+res_1+"解密得到: "+res_2);

        String res_3 = encryptInputBinary(str_2, key);
        System.out.println("明文10101010101010101010101010101010加密得到: "+res_3);
        String res_4 = decryptInputBinary(res_3, key);
        System.out.println("密文"+res_3+"解密得到: "+res_4);

        String res_5 = encryptInputAscii(str_3, key);
        System.out.println("明文AB加密得到: "+res_5);
        String res_6 = decryptInputAscii(res_5, key);
        System.out.println("密文"+res_5+"解密得到: "+res_6);


        String res_7 = encryptInputAscii(str_4, key);
        System.out.println("明文ABCD加密得到: "+res_7);
        String res_8 = decryptInputAscii(res_7, key);
        System.out.println("密文"+res_7+"解密得到: "+res_8);

        //最终测试
        System.out.println("最终测试: ");
        String st_1 = Encrypt(str_1, key);
        System.out.println("明文1010101010101010加密得到: "+st_1);
        String st_2 = Decrypt(st_1, key);
        System.out.println("密文"+st_1+"解密得到: "+st_2);

        String st_3 = Encrypt(str_2, key);
        System.out.println("明文10101010101010101010101010101010加密得到: "+st_3);
        String st_4 = Decrypt(st_3, key);
        System.out.println("密文"+st_3+"解密得到: "+st_4);

        String st_5 = Encrypt(str_3, key);
        System.out.println("明文AB加密得到: "+st_5);
        String st_6 = Decrypt(st_5, key);
        System.out.println("密文"+st_5+"解密得到: "+st_6);


        String st_7 = Encrypt(str_4, key);
        System.out.println("明文ABCD加密得到: "+st_7);
        String st_8 = Decrypt(st_7, key);
        System.out.println("密文"+st_7+"解密得到: "+st_8);

    }
}

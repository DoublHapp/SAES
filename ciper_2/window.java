import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

public class window {
    private JPanel panel1;
    private JTextArea plaintext;
    private JTextArea ciphertext;
    private JTextArea key;
    private JTextArea output;
    private JButton encryptButton;
    private JButton decryptButton;
    private JTextArea IV;
    private JButton doubleEncryptButton;
    private JButton tripleEncryptButton;
    private JButton meetHackButton;
    private JButton CBCEncryptButton;
    private JButton CBCDecryptButton;
    private JButton doubleDecryptButton;
    private JButton tripleDecryptButton;

    //输出
    private void print(String str){
        String text=output.getText()+str+"\n";
        output.setText(text);
    }

    /**
     * 获得当前输入的密钥并解析为Long类型
     * @param length 需要的密钥长度，输入高于这个长度则会抛出错误，低于这个长度在左侧自动补零
     * @return 返回解析后的Long类型密钥
     * @throws Exception 随便抛出的错误
     */
    private long getKey(int length) throws Exception {
        String s=key.getText();
        if(s.startsWith("0x")|| s.startsWith("0X")){
            s=s.substring(2);
            long result=Long.parseLong(s,16);

            String binaryString=Long.toBinaryString(result);
            if(binaryString.length()>length){
                throw new Exception();
            }
            return result;
        }else{
            if(s.length()>length){
                throw new Exception();
            }
            return Long.parseLong(s,2);
        }
    }

    /**
     * 获得当前输入的IV并解析为Long类型
     * 长度受CBC.BLOCK_SIZE限制，超出则会抛出错误
     * @return 返回解析后的Long类型IV
     * @throws Exception 随便抛出的错误
     */
    private long getIV() throws Exception {
        String s=IV.getText();
        int length=CBC.BLOCK_SIZE;
        if(s.startsWith("0x")|| s.startsWith("0X")){
            s=s.substring(2);
            long result=Long.parseLong(s,16);

            String binaryString=Long.toBinaryString(result);
            if(binaryString.length()>length){
                throw new Exception();
            }
            return result;
        }else{
            if(s.length()>length){
                throw new Exception();
            }
            return Long.parseLong(s,2);
        }
    }
    public window() {
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String p=plaintext.getText();

                try{
                    long k=getKey(16);
                    String result=SAES.Encrypt(p,k);
                    print("密文：   "+result);
                } catch (Exception ex) {
                    print("错误：明文或密钥不合法");
                }
            }
        });
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String c=ciphertext.getText();

                try{
                    long k=getKey(16);
                    String result=SAES.Decrypt(c,k);
                    print("明文：   "+result);
                } catch (Exception ex) {
                    print("错误：密文或密钥不合法");
                }
            }
        });
        doubleEncryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String p=plaintext.getText();

                try{
                    long k=getKey(32);
                    String result=SAES.DoubleEncrypt(p,k);
                    print("密文：   "+result);
                } catch (Exception ex) {
                    print("错误：明文或密钥不合法");
                }
            }
        });
        doubleDecryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String c=ciphertext.getText();

                try{
                    long k=getKey(32);
                    String result=SAES.DoubleDecrypt(c,k);
                    print("明文：   "+result);
                } catch (Exception ex) {
                    print("错误：密文或密钥不合法");
                }
            }
        });
        tripleEncryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String p=plaintext.getText();

                try{
                    long k=getKey(48);
                    String result=SAES.TripleEncrypt(p,k);
                    print("密文：   "+result);
                } catch (Exception ex) {
                    print("错误：明文或密钥不合法");
                }
            }
        });
        tripleDecryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String c=ciphertext.getText();

                try{
                    long k=getKey(48);
                    String result=SAES.TripleDecrypt(c,k);
                    print("明文：   "+result);
                } catch (Exception ex) {
                    print("错误：密文或密钥不合法");
                }
            }
        });
        meetHackButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String p=plaintext.getText();
                String c=ciphertext.getText();

                try{
                    List<Long> result=BruteForceSAES.meetInTheMiddle(p,c);
                    StringBuilder str= new StringBuilder("可能的密钥有：");
                    for (Long aLong : result) {
                        StringBuilder s= new StringBuilder(Long.toBinaryString(aLong));
                        for(int i=s.length();i<32;i++){
                            s.insert(0, '0');
                        }
                        str.append(s).append("、");
                    }
                    print(str.toString());
                } catch (Exception ex) {
                    print("错误：明密文对不合法");
                }
            }
        });
        CBCEncryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String p=plaintext.getText();

                try{
                    long k=getKey(16);
                    long iv=getIV();
                    String result=CBC.Encrypt(p,k,iv);
                    print("密文：  "+result);
                    print("密文（16进制）：  0x"+Long.toHexString(Long.parseLong(result,2)));
                } catch (Exception ex) {
                    print("错误：明文、密钥或IV不合法");
                }
            }
        });
        CBCDecryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String c=ciphertext.getText();

                try{
                    long k=getKey(16);
                    long iv=getIV();
                    String result=CBC.Decrypt(c,k,iv);
                    print("明文：  "+result);
                    print("明文（16进制）：  0x"+Long.toHexString(Long.parseLong(result,2)));
                } catch (Exception ex) {
                    print("错误：密文、密钥或IV不合法");
                }
            }
        });
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("window");
        frame.setContentPane(new window().panel1);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//        frame.pack();
        frame.setSize(1200,800);
        frame.setVisible(true);
    }
}

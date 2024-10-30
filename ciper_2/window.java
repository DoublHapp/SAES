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
    private JButton CBCEntryptButton;
    private JButton CBCDecryptButton;
    private JButton ddoubleDecryptButton;
    private JButton tripleDecryptButton;

    private void print(String str){
        String text=output.getText()+str+"\n";
        output.setText(text);
    }
    public window() {
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String p=plaintext.getText();

                if(key.getText().length()!=16){
                    print("密钥不合法，需要为16位2进制数");
                    return;
                }
                try{
                    long k=Long.parseLong(key.getText(),2);
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

                if(key.getText().length()!=16){
                    print("密钥不合法，需要为16位2进制数");
                    return;
                }
                try{
                    long k=Long.parseLong(key.getText(),2);
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

                if(key.getText().length()!=32){
                    print("密钥不合法，需要为32位2进制数");
                    return;
                }
                try{
                    long k=Long.parseLong(key.getText(),2);
                    String result=SAES.DoubleEncrypt(p,k);
                    print("密文：   "+result);
                } catch (Exception ex) {
                    print("错误：明文或密钥不合法");
                }
            }
        });
        ddoubleDecryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String c=ciphertext.getText();

                if(key.getText().length()!=32){
                    print("密钥不合法，需要为32位2进制数");
                    return;
                }
                try{
                    long k=Long.parseLong(key.getText(),2);
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

                if(key.getText().length()!=48){
                    print("密钥不合法，需要为48位2进制数");
                    return;
                }
                try{
                    long k=Long.parseLong(key.getText(),2);
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

                if(key.getText().length()!=48){
                    print("密钥不合法，需要为48位2进制数");
                    return;
                }
                try{
                    long k=Long.parseLong(key.getText(),2);
                    String result=SAES.TripleDecrypt(c,k);
                    print("明文：   "+result);
                } catch (NumberFormatException ex) {
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
                        str.append(aLong).append("、");
                    }
                    print(str.toString());
                } catch (Exception ex) {
                    print("错误：明密文对不合法");
                }
            }
        });
        CBCEntryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String p=plaintext.getText();
                if(key.getText().length()!=16){
                    print("密钥不合法，需要为16位2进制数");
                    return;
                }
                if(IV.getText().length()!=CBC.BLOCK_SIZE){
                    print("IV不合法，需要为"+CBC.BLOCK_SIZE+"位2进制数");
                }

                try{
                    long k= Long.parseLong(key.getText(),2);
                    long iv= Long.parseLong(IV.getText(),2);
                    String result=CBC.Encrypt(p,k,iv);
                    print("密文：  "+result);
                } catch (Exception ex) {
                    print("错误：明文、密钥或IV不合法");
                }
            }
        });
        CBCDecryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String c=ciphertext.getText();
                if(key.getText().length()!=16){
                    print("密钥不合法，需要为16位2进制数");
                    return;
                }
                if(IV.getText().length()!=CBC.BLOCK_SIZE){
                    print("IV不合法，需要为"+CBC.BLOCK_SIZE+"位2进制数");
                }

                try{
                    long k= Long.parseLong(key.getText(),2);
                    long iv= Long.parseLong(IV.getText(),2);
                    String result=CBC.Decrypt(c,k,iv);
                    print("明文：  "+result);
                } catch (NumberFormatException ex) {
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

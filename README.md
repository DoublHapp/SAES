# SAES
本项目是一次信息安全导论实验，根据简单的加解密算法SAES进行设计，详情请见石墨文档[SAES](https://shimo.im/docs/zm1FlCxE3eYCQSSo?fallback=1)。
## 简单的加解密模块
[SAES.java](ciper_2/SAES.java)：该文件中定义并实现了SAES算法的加密、解密功能,并且扩展实现了双重加密和三重加密。
## 中间相遇攻击破解SAES
[BruteForceSAES.java](ciper_2/BruteForceSAES.java)：该文件中定义并实现了针对SAES算法的暴力破解密钥功能,同时实现了针对SAES双重加密的中间相遇攻击。 
## CBC密码分组链模式应用
[CBC.java](ciper_2/CBC.java)：该文件中定义并实现了基于SAES算法的密码分组链(CBC)模式应用。
## GUI设计
[window.java](ciper_2/window.java)：该文件中定义并实现了用户界面，便于进行执行加解密以及破解等功能。
## 过关测试结果
### 第1关：基本测试
该项目根据S-AES算法编写和调试程序，提供GUI解密支持用户交互。输入可以是16bit的数据和16bit的密钥，输出是16bit的密文。  
![Test1_Image](测试图片/Test1_Image.png)
### 第2关：交叉测试
考虑到SAES是算法标准，所有人在编写程序的时候需要使用相同算法流程和转换单元(替换盒、列混淆矩阵等)，以保证算法和程序在异构的系统或平台上都可以正常运行。  
我们寻找到了另外一个小组进行交叉加解密测试。测试结果截图如下：  
![Test2_Image1](测试图片/Test2_Image1.jpg)  
![Test2_Image2](测试图片/Test2_Image2.jpg)  
![Test2_Image3](测试图片/Test2_Image3.png)  
![Test2_Image4](测试图片/Test2_Image4.png)
### 第3关：扩展功能
考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为2 Byte)，对应地输出也可以是ACII字符串(很可能是乱码)。展示效果可见第2关测试。
### 第4关：多重加密
#### 双重加密
将S-AES算法通过双重加密进行扩展，分组长度仍然是16 bits，但密钥长度为32 bits。
#### 中间相遇攻击
假设你找到了使用相同密钥的明、密文对(一个或多个)，请尝试使用中间相遇攻击的方法找到正确的密钥Key(K1+K2)。

![Test4_Image](测试图片/Test4_Image1.png)
#### 三重加密
将S-AES算法通过三重加密进行扩展，使用48bits(K1+K2+K3)的模式进行三重加解密。

![Test4_Image](测试图片/Test4_Image2.png)
### 第5关：工作模式
基于S-AES算法，使用密码分组链(CBC)模式对较长的明文消息进行加密。注意初始向量(16 bits) 的生成，并需要加解密双方共享。
在CBC模式下进行加密，并尝试对密文分组进行替换或修改，然后进行解密，请对比篡改密文前后的解密结果。

![Test5_Image](测试图片/Test5_Image.png)

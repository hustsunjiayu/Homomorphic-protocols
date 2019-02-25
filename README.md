# Paillier based Homomorphic-protocols
Some Homomorphic protocols on semihonest Hybrid Cloud based on Pailliar cryptosystem. And you can also find all basic functions in Paillier cryptosystem, such as keyGeneration(), Encryption(), Decryption() and so on.

The protocols implement homomorphic operations including:
1. add(not a protocol but local)
2. sub(not a protocol but local)
3. mul(a*b, a is encrypted, b can be encrypted or not encrypted, the latter is faster because it's local)
4. divide(a/b, a is encrypted, b can be encrypted or not encrypted, the latter is faster)
5. compare(if a>=b)
6. equal(if a==b)
7. bitDecomposition
8. ifOdd
9. xor or and (the input parameters must be 0 or 1 before encrypted)
10. and so on....

More details about the theories:
Zhao Y, Yang L T, Sun J. A Secure High-Order CFS Algorithm on Clouds for Industrial Internet-of-Things[J]. IEEE Transactions on Industrial Informatics, 2018, PP(99):1-1.

The 2 java profiles are a demo of a semihonest Hybrid Cloud, both of them have one main function and some test code for the protocols.

The protocols are based on socket.

一些半诚实混合云上基于Pailliar加密体系的同态协议。也包含了Pailliar加密体系所有必要的基本函数：密钥生成、加密、解密等

这些协议实现的同态操作包括：
1. 加法(是本地运算，非通信协议)
2. 减法(是本地运算，非通信协议)
3. 乘法(a*b，a加密，b可加密可不加密,后者更快，因为是本地运算无需通信)
4. 除法(a/b，a加密，b可加密可不加密,后者更快)
5. 比较(if a>=b)
6. 相等(if a==b)
7. 位分解
8. 是否为偶数
9. xor or and (输入必须是0或1的加密)
10. 更多……

详细理论细节见：
Zhao Y, Yang L T, Sun J. A Secure High-Order CFS Algorithm on Clouds for Industrial Internet-of-Things[J]. IEEE Transactions on Industrial Informatics, 2018, PP(99):1-1.

两个java文件是半诚实混合云的一个demo，都有main函数以及一些协议的测试代码。

协议的通信基于socket

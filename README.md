# Paillier based Homomorphic-protocols
Some Homomorphic protocols on semihonest Hybrid Cloud based on Pailliar cryptosystem, and you can also find all basic functions in Paillier cryptosystem, such as keyGeneration(), Encryption(), Decryption() and so on.

The protocols implement homomorphic operations including:
1. add(not a protocol but local)
2. sub(not a protocol but local)
3. mul(a*b, a is encrypted, b can be encrypted or not encrypted, the latter is faster because it's local)
4. divide(a/b, a is encrypted, b can be encrypted or not encrypted, the latter is faster)
5. compare(if a>=b)
6. equal(if a==b)
7. bitDecomposition
8. ifOdd
9. xor or and (the input parameters must be 1bit before encrypted)
10. and so on....

More details about the theories:
Zhao Y, Yang L T, Sun J. A Secure High-Order CFS Algorithm on Clouds for Industrial Internet-of-Things[J]. IEEE Transactions on Industrial Informatics, 2018, PP(99):1-1.

The 2 java profiles are a demo of a semihonest Hybrid Cloud, both of them have one main function and some test code for the protocols.

The protocols are based on socket.

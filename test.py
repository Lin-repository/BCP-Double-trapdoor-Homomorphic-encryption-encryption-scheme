import BCP
if __name__ == "__main__":

    bcp = BCP()
    mk = bcp.GetMK()
    print("mk is:",mk)
    pk,sk = bcp.KeyGen()
    print("------------------------")
    print("pk is:",pk,"sk is:",sk)
    plaintext = 1024
    print("------------------------")
    print("plaintext is:",plaintext)
    ciphertext = bcp.Encrypt(pk,plaintext)
    print("-------------------------")
    print("ciphertext is:",ciphertext)
    m1 = bcp.Decrypt(ciphertext,sk)
    print("-------------------------")
    print("Using sk to decrypt ciphertext,result is:",m1)
    m2 = bcp.DecryptMK(ciphertext,mk,pk)
    print("-------------------------")
    print("Using mk to decrypt ciphertext,result is:",m2)
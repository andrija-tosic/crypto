namespace Cryptography.Ciphers;
public interface IBlockCipher
{
    public byte[] Encrypt(byte[] data);
    public byte[] Decrypt(byte[] data);
}

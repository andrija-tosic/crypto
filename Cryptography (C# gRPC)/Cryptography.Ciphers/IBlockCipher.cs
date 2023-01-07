namespace Cryptography.Ciphers;
public interface IBlockCipher
{
    int BlockBytes { get; set; }
    Span<byte> Key { get; }
    public abstract byte[] Encrypt(byte[] data);
    public abstract byte[] Decrypt(byte[] data);
    public abstract byte[] EncryptBlock(byte[] data, Span<byte> key);
    public abstract byte[] DecryptBlock(byte[] data, Span<byte> key);
}

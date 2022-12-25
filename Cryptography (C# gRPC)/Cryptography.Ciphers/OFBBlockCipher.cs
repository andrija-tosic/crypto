namespace Cryptography.Ciphers;
public class OFBBlockCipher : IDisposable
{
    private readonly IBlockCipher blockCipher;

    private readonly byte[] key;
    private byte[] outputFeedback;

    public OFBBlockCipher(IBlockCipher blockCipher, byte[] key, byte[] IV)
    {
        this.blockCipher = blockCipher;
        this.key = key;
        outputFeedback = (byte[])IV.Clone();
    }

    public byte[] Encrypt(byte[] plaintext)
    {
        outputFeedback = blockCipher.Encrypt(outputFeedback, key);

        byte[] ciphertext = new byte[plaintext.Length];

        for (int i = 0; i < plaintext.Length; i++)
        {
            ciphertext[i] = (byte)(plaintext[i] ^ outputFeedback[i]);
        }

        return ciphertext;
    }

    public byte[] Decrypt(byte[] plaintext)
    {
        return Encrypt(plaintext);
    }
    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}
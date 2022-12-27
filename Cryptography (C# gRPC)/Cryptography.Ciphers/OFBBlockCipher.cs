namespace Cryptography.Ciphers;
public class OFBBlockCipher : IDisposable
{
    private readonly IBlockCipher blockCipher;

    private byte[] outputFeedback;

    public OFBBlockCipher(IBlockCipher blockCipher, byte[] IV)
    {
        this.blockCipher = blockCipher;
        this.outputFeedback = (byte[])IV.Clone();
    }

    public byte[] Encrypt(byte[] plaintext)
    {
        this.outputFeedback = this.blockCipher.Encrypt(this.outputFeedback);

        byte[] ciphertext = new byte[plaintext.Length];

        for (int i = 0; i < plaintext.Length; i++)
        {
            ciphertext[i] = (byte)(plaintext[i] ^ this.outputFeedback[i]);
        }

        return ciphertext;
    }

    public byte[] Decrypt(byte[] plaintext)
    {
        return this.Encrypt(plaintext);
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}
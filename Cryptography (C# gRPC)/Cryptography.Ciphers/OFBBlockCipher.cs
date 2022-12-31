namespace Cryptography.Ciphers;
public class OFBBlockCipher : IDisposable
{
    private readonly IBlockCipher blockCipher;

    private byte[] outputFeedback;

    private ByteBlockSplitter blockSplitter;

    public OFBBlockCipher(IBlockCipher blockCipher, byte[] IV)
    {
        this.blockCipher = blockCipher;
        this.outputFeedback = (byte[])IV.Clone();

        this.blockSplitter = new ByteBlockSplitter(IV.Length);
    }

    public IEnumerable<byte[]> Encrypt(byte[] plaintext)
    {
        if (plaintext.Length == 0)
        {
            yield return plaintext;
        }

        foreach (byte[] block in this.blockSplitter.Split(plaintext))
        {
            this.outputFeedback = this.blockCipher.EncryptBlock(this.outputFeedback, this.blockCipher.Key);

            byte[] ciphertext = new byte[this.outputFeedback.Length];

            for (int i = 0; i < this.outputFeedback.Length; i++)
            {
                ciphertext[i] = (byte)(block[i] ^ this.outputFeedback[i]);
            }

            yield return ciphertext;
        }
    }

    public byte[] Finish()
    {
        byte[] leftOverBytes = this.blockSplitter.Flush();

        this.outputFeedback = this.blockCipher.EncryptBlock(this.outputFeedback, this.blockCipher.Key);

        byte[] ciphertext = new byte[this.outputFeedback.Length];

        for (int i = 0; i < leftOverBytes.Length; i++)
        {
            ciphertext[i] = (byte)(leftOverBytes[i] ^ this.outputFeedback[i]);
        }

        return leftOverBytes;
    }

    public IEnumerable<byte[]> Decrypt(byte[] plaintext)
    {
        return this.Encrypt(plaintext);
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}
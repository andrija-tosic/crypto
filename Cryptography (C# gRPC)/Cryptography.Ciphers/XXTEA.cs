namespace Cryptography.Ciphers;
public class XXTEA : IBlockCipher
{
    private const uint Delta = 0x9E3779B9;
    private readonly uint[] key;

    private List<byte> lastBlockBuffer;
    private long messageLength;
    private long paddedMessageLength;
    public int BlockBytes { get; set; }
    public byte[] Key { get { return this.key.ToByteArray(); } }
    private ByteBlockSplitter blockSplitter;
    
    public XXTEA(byte[] key, long messageLength, int blockSize)
    {
        if (blockSize < 8)
        {
            throw new ArgumentOutOfRangeException("XXTEA block size must be greater or equal to 8.");
        }

        this.BlockBytes = blockSize;

        this.key = new uint[4];
        Buffer.BlockCopy(key, 0, this.key, 0, 16);

        this.lastBlockBuffer = new List<byte>(this.BlockBytes);

        this.messageLength = messageLength;
        this.paddedMessageLength = this.messageLength + this.BlockBytes - 1;
        this.paddedMessageLength -= this.paddedMessageLength % this.BlockBytes;

        this.lastBlockBuffer.AddRange(BitConverter.GetBytes(messageLength));

        this.blockSplitter = new(this.BlockBytes);
        this.blockSplitter.PrependData(BitConverter.GetBytes(messageLength));
    }

    public XXTEA(byte[] key, int blockSize)
    {
        this.BlockBytes = Math.Max(blockSize, 8);

        this.key = new uint[4];
        Buffer.BlockCopy(key, 0, this.key, 0, 16);

        this.lastBlockBuffer = new List<byte>(this.BlockBytes);

        this.messageLength = -1;

        this.blockSplitter = new(this.BlockBytes);
    }

    public byte[] Encrypt(byte[] data)
    {
        if (data.Length == 0)
        {
            return data;
        }

        var encryptedBytes = new List<byte>();

        foreach (byte[] block in this.blockSplitter.SplitToBlocks(data))
        {
            uint[] res = block.ToUInt32Array();
            EncryptBlock(ref res, this.key);

            encryptedBytes.AddRange(res.ToByteArray());
        }

        return encryptedBytes.ToArray();
    }

    public byte[] Decrypt(byte[] data)
    {
        if (data.Length == 0)
        {
            return data;
        }

        var decryptedBytes = new List<byte>();

        foreach (byte[] block in this.blockSplitter.SplitToBlocks(data))
        {

            uint[] res = block.ToUInt32Array();
            DecryptBlock(ref res, this.key);

            byte[] currentBlock = res.ToByteArray();

            if (this.messageLength == -1)
            {
                this.messageLength = BitConverter.ToInt64(currentBlock.AsSpan()[0..sizeof(long)]);

                this.paddedMessageLength = this.messageLength + this.BlockBytes - 1;
                this.paddedMessageLength -= this.paddedMessageLength % this.BlockBytes;

                currentBlock = currentBlock[sizeof(long)..];
            }

            decryptedBytes.AddRange(currentBlock);
        }

        return decryptedBytes.ToArray();
    }

    public byte[] FinishEncryption()
    {
        /* Pad to block size and encrypt. */

        byte[] data = this.blockSplitter.Flush();

        uint[] v = new uint[this.BlockBytes / sizeof(uint)];

        Buffer.BlockCopy(data, 0, v, 0, data.Length);

        EncryptBlock(ref v, this.key);

        this.lastBlockBuffer.Clear();

        return v.ToByteArray();
    }

    public byte[] FinishDecryption()
    {
        /* Decrypt block and remove padding. */

        long padLength = this.paddedMessageLength - sizeof(long) - this.messageLength;

        byte[] data = this.blockSplitter.Flush();

        uint[] v = new uint[this.BlockBytes / sizeof(uint)];

        Buffer.BlockCopy(data, 0, v, 0, data.Length);

        DecryptBlock(ref v, this.key);

        byte[] res = new byte[this.BlockBytes - padLength];

        Buffer.BlockCopy(v, 0, res, 0, this.BlockBytes - (int)padLength);

        this.lastBlockBuffer.Clear();

        return res;
    }

    public static void EncryptBlock(ref uint[] v, uint[] k)
    {
        int n = v.Length - 1;
        if (n < 1)
        {
            return;
        }

        uint z = v[n];
        _ = v[0];
        uint sum = 0, e;
        int p, q = 6 + 52 / (n + 1);
        while (q-- > 0)
        {
            sum += Delta;
            e = (sum >> 2) & 3;
            uint y;
            for (p = 0; p < n; p++)
            {
                y = v[p + 1];
                z = v[p] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
            }

            y = v[0];
            z = v[n] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
        }
    }

    public static void DecryptBlock(ref uint[] v, uint[] k)
    {
        int n = v.Length - 1;
        if (n < 1)
        {
            return;
        }

        _ = v[n];
        uint y = v[0], sum, e;
        int p, q = 6 + 52 / (n + 1);
        sum = (uint)(q * Delta);
        while (sum != 0)
        {
            e = (sum >> 2) & 3;
            uint z;
            for (p = n; p > 0; p--)
            {
                z = v[p - 1];
                y = v[p] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
            }

            z = v[n];
            y = v[0] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
            sum -= Delta;
        }
    }

    public byte[] EncryptParallel(byte[] data, int numThreads)
    {
        if (data.Length == 0)
        {
            return data;
        }

        var encryptedBytes = new List<byte>();

        byte[][] blocks = this.blockSplitter.SplitToBlocks(data).ToArray();

        uint[][] blocksUInt32 = new uint[blocks.Length][];

        for (int i = 0; i < blocks.Length; i++)
        {
            blocksUInt32[i] = blocks[i].ToUInt32Array();
        }

        _ = Parallel.For(0, blocksUInt32.Length, new ParallelOptions { MaxDegreeOfParallelism = numThreads }, i =>
        {
            int blockIndex = i;
            EncryptBlock(ref blocksUInt32[blockIndex], this.key);
        });

        for (int i = 0; i < blocksUInt32.Length; i++)
        {
            encryptedBytes.AddRange(blocksUInt32[i].ToByteArray());
        }

        return encryptedBytes.ToArray();
    }

    public byte[] DecryptParallel(byte[] data, int numThreads)
    {
        if (data.Length == 0)
        {
            return data;
        }

        var decryptedBytes = new List<byte>();

        byte[][] blocks = this.blockSplitter.SplitToBlocks(data).ToArray();

        uint[][] blocksUInt32 = new uint[blocks.Length][];

        for (int i = 0; i < blocks.Length; i++)
        {
            blocksUInt32[i] = blocks[i].ToUInt32Array();
        }

        _ = Parallel.For(0, blocksUInt32.Length, new ParallelOptions { MaxDegreeOfParallelism = numThreads }, i =>
        {
            int blockIndex = i;
            DecryptBlock(ref blocksUInt32[blockIndex], this.key);
        });

        for (int i = 0; i < blocksUInt32.Length; i++)
        {
            decryptedBytes.AddRange(blocksUInt32[i].ToByteArray());
        }

        if (this.messageLength == -1)
        {
            this.messageLength = BitConverter.ToInt64(decryptedBytes.GetRange(0, sizeof(long)).ToArray());

            this.paddedMessageLength = this.messageLength + this.BlockBytes - 1;
            this.paddedMessageLength -= this.paddedMessageLength % this.BlockBytes;

            decryptedBytes = decryptedBytes.GetRange(sizeof(long), decryptedBytes.Count - sizeof(long));
        }

        return decryptedBytes.ToArray();
    }

    public byte[] EncryptBlock(byte[] data, byte[] key)
    {
        uint[] keyUInt32 = key.ToUInt32Array();
        uint[] dataUInt32 = data.ToUInt32Array();

        EncryptBlock(ref dataUInt32, keyUInt32);

        return dataUInt32.ToByteArray();
    }

    public byte[] DecryptBlock(byte[] data, byte[] key)
    {
        uint[] keyUInt32 = key.ToUInt32Array();
        uint[] dataUInt32 = data.ToUInt32Array();

        DecryptBlock(ref dataUInt32, keyUInt32);

        return dataUInt32.ToByteArray();
    }
}

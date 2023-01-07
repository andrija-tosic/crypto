using System.Runtime.InteropServices;

namespace Cryptography.Ciphers;
public class XXTEA : IBlockCipher
{
    private const uint Delta = 0x9E3779B9;
    private readonly uint[] key;

    private long messageLength;
    private long paddedMessageLength;
    public int BlockBytes { get; set; }
    public Span<byte> Key { get { return this.key.AsSpan().AsByteSpan(); } }
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

        this.messageLength = messageLength;
        this.paddedMessageLength = this.messageLength + sizeof(long) + this.BlockBytes - 1;
        this.paddedMessageLength -= this.paddedMessageLength % this.BlockBytes;

        this.blockSplitter = new(this.BlockBytes);
        this.blockSplitter.PrependData(BitConverter.GetBytes(messageLength));
    }

    public XXTEA(byte[] key, int blockSize)
    {
        this.BlockBytes = Math.Max(blockSize, 8);

        this.key = new uint[4];
        Buffer.BlockCopy(key, 0, this.key, 0, 16);

        this.messageLength = -1;

        this.blockSplitter = new(this.BlockBytes);
    }

    public byte[] Encrypt(byte[] data)
    {
        if (data.Length == 0)
        {
            return data;
        }

        var encryptedBytes = new List<byte>((int)Math.Ceiling((double)data.Length / this.BlockBytes));

        foreach (byte[] block in this.blockSplitter.SplitToBlocks(data))
        {
            Span<uint> res = block.AsSpan().AsUInt32Span();
            EncryptBlockInternal(res, this.key);

            encryptedBytes.AddRange(res.AsByteSpan().ToArray());
        }

        return encryptedBytes.ToArray();
    }

    public byte[] Decrypt(byte[] data)
    {
        if (data.Length == 0)
        {
            return data;
        }

        var decryptedBytes = new List<byte>((int)Math.Ceiling((double)data.Length / this.BlockBytes));

        foreach (byte[] block in this.blockSplitter.SplitToBlocks(data))
        {
            Span<uint> res = block.AsSpan().AsUInt32Span();
            DecryptBlockInternal(res, this.key);

            Span<byte> currentBlock = res.AsByteSpan();

            if (this.messageLength == -1)
            {
                this.messageLength = BitConverter.ToInt64(currentBlock[0..sizeof(long)]);

                this.paddedMessageLength = this.messageLength + sizeof(long) + this.BlockBytes - 1;
                this.paddedMessageLength -= this.paddedMessageLength % this.BlockBytes;

                currentBlock = currentBlock[sizeof(long)..];
            }

            decryptedBytes.AddRange(currentBlock.ToArray());
        }

        return decryptedBytes.ToArray();
    }

    public Span<byte> FinishEncryption()
    {
        /* Pad to block size and encrypt. */

        byte[] data = this.blockSplitter.Flush();

        if (data.Length == 0)
        {
            return data;
        }

        uint[] v = new uint[(int)Math.Ceiling((double)this.BlockBytes / sizeof(uint))];

        Buffer.BlockCopy(data, 0, v, 0, data.Length);

        EncryptBlockInternal(v, this.key);

        return v.AsSpan().AsByteSpan();
    }

    public Span<byte> FinishDecryption()
    {
        /* Decrypt block and remove padding. */

        long padLength;

        if (this.paddedMessageLength == this.messageLength)
        {
            return Array.Empty<byte>();
        }
        else
        {
            padLength = this.paddedMessageLength - sizeof(long) - this.messageLength;
        }

        byte[] data = this.blockSplitter.Flush();

        uint[] v = new uint[(int)Math.Ceiling((double)this.BlockBytes / sizeof(uint))];

        Buffer.BlockCopy(data, 0, v, 0, data.Length);

        DecryptBlockInternal(v, this.key);

        Span<byte> res = v.AsSpan().AsByteSpan()[..(int)(this.BlockBytes - padLength)];

        return res;
    }

    private static void EncryptBlockInternal(Span<uint> v, Span<uint> k)
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
                z = v[p] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(int)((p & 3) ^ e)] ^ z));
            }

            y = v[0];
            z = v[n] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(int)((p & 3) ^ e)] ^ z));
        }
    }

    private static void DecryptBlockInternal(Span<uint> v, Span<uint> k)
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
                y = v[p] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(int)((p & 3) ^ e)] ^ z));
            }

            z = v[n];
            y = v[0] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(int)((p & 3) ^ e)] ^ z));
            sum -= Delta;
        }
    }

    public byte[] EncryptParallel(byte[] data, int numThreads)
    {
        if (data.Length == 0)
        {
            return data;
        }

        byte[][] blocks = this.blockSplitter.SplitToBlocks(data).ToArray();

        byte[] encryptedBytes = new byte[blocks.Length * this.BlockBytes];

        uint[][] blocksUInt32 = new uint[blocks.Length][];

        for (int i = 0; i < blocks.Length; i++)
        {
            blocksUInt32[i] = blocks[i].ToUInt32Array();
        }

        _ = Parallel.For(0, blocksUInt32.Length, new ParallelOptions { MaxDegreeOfParallelism = numThreads }, i =>
        {
            int blockIndex = i;
            EncryptBlockInternal(blocksUInt32[blockIndex], this.key);
        });

        for (int i = 0; i < blocksUInt32.Length; i++)
        {
            Buffer.BlockCopy(blocksUInt32[i], 0, encryptedBytes, i * this.BlockBytes, this.BlockBytes);
        }

        return encryptedBytes;
    }

    public byte[] DecryptParallel(byte[] data, int numThreads)
    {
        if (data.Length == 0)
        {
            return data;
        }

        byte[][] blocks = this.blockSplitter.SplitToBlocks(data).ToArray();
        uint[][] blocksUInt32 = new uint[blocks.Length][];

        for (int i = 0; i < blocks.Length; i++)
        {
            blocksUInt32[i] = blocks[i].ToUInt32Array();
        }

        _ = Parallel.For(0, blocksUInt32.Length, new ParallelOptions { MaxDegreeOfParallelism = numThreads }, i =>
        {
            int blockIndex = i;
            DecryptBlockInternal(blocksUInt32[blockIndex].AsSpan(), this.key);
        });

        byte[] decryptedBytes = new byte[blocks.Length * this.BlockBytes];

        for (int i = 0; i < blocksUInt32.Length; i++)
        {
            Buffer.BlockCopy(blocksUInt32[i], 0, decryptedBytes, i * this.BlockBytes, this.BlockBytes);
        }

        if (this.messageLength == -1)
        {
            this.messageLength = BitConverter.ToInt64(decryptedBytes, 0);

            this.paddedMessageLength = this.messageLength + sizeof(long) + this.BlockBytes - 1;
            this.paddedMessageLength -= this.paddedMessageLength % this.BlockBytes;

            decryptedBytes = decryptedBytes[sizeof(long)..];
        }

        return decryptedBytes;
    }

    public byte[] EncryptBlock(byte[] data, Span<byte> key)
    {
        Span<uint> keyUInt32 = key.AsUInt32Span();
        Span<uint> dataUInt32 = data.AsSpan().AsUInt32Span();

        EncryptBlockInternal(dataUInt32, keyUInt32);

        return dataUInt32.AsByteSpan().ToArray();
    }

    public byte[] DecryptBlock(byte[] data, Span<byte> key)
    {
        Span<uint> keyUInt32 = key.AsUInt32Span();
        Span<uint> dataUInt32 = data.AsSpan().AsUInt32Span();

        DecryptBlockInternal(dataUInt32, keyUInt32);

        return dataUInt32.AsByteSpan().ToArray();
    }
}

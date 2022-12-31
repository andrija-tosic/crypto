using System.Diagnostics;

namespace Cryptography.Ciphers;
public class XXTEA : IBlockCipher
{
    private const uint Delta = 0x9E3779B9;
    private readonly uint[] key;

    private List<byte> lastBlockBuffer;
    private long messageLength;
    private long paddedMessageLength;
    private long receivedBytes = 0;
    public int BlockBytes { get; set; }
    public byte[] Key { get { return this.key.ToByteArray(); } }

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
        this.paddedMessageLength -= (paddedMessageLength % this.BlockBytes);

        this.lastBlockBuffer.AddRange(BitConverter.GetBytes(messageLength));
    }

    public XXTEA(byte[] key, int blockSize)
    {
        this.BlockBytes = Math.Max(blockSize, 8);

        this.key = new uint[4];
        Buffer.BlockCopy(key, 0, this.key, 0, 16);

        this.lastBlockBuffer = new List<byte>(this.BlockBytes);

        this.messageLength = -1;
    }

    public byte[] Encrypt(byte[] data)
    {
        if (data.Length == 0)
        {
            return data;
        }

        this.receivedBytes += data.LongLength;

        byte[] fullBuffer = new byte[this.lastBlockBuffer.Count + data.Length];

        /* Prepend the last leftover bytes to new data. */
        Buffer.BlockCopy(this.lastBlockBuffer.ToArray(), 0, fullBuffer, 0, this.lastBlockBuffer.Count);
        Buffer.BlockCopy(data, 0, fullBuffer, this.lastBlockBuffer.Count, data.Length);

        byte[][] blocks = fullBuffer.SplitIntoBlocksOfSize(this.BlockBytes);

        int fullSizedBlocksCount;

        if (blocks[^1].Length == this.BlockBytes)
        {
            fullSizedBlocksCount = blocks.Length;
            this.lastBlockBuffer.Clear();
        }
        else
        {
            fullSizedBlocksCount = blocks.Length - 1;

            /* Save the block of length < BlockSize. */
            this.lastBlockBuffer = blocks[^1].ToList();
        }

        byte[] encryptedBytes = new byte[this.BlockBytes * fullSizedBlocksCount];

        /* Last block may be of length < BlockSize. */
        /* Process all of the BlockSize blocks. */
        for (int i = 0; i < fullSizedBlocksCount; i++)
        {
            Debug.Assert(blocks[i].Length == this.BlockBytes);

            uint[] res = blocks[i].ToUInt32Array();
            EncryptBlock(ref res, this.key);

            Buffer.BlockCopy(res, 0, encryptedBytes, i * this.BlockBytes, res.Length * sizeof(uint));
        }

        if (this.receivedBytes == this.messageLength)
        {
            byte[] lastData = this.FinishEncryption();
            byte[] res = new byte[this.BlockBytes * fullSizedBlocksCount + lastData.Length];

            Buffer.BlockCopy(encryptedBytes, 0, res, 0, encryptedBytes.Length);
            Buffer.BlockCopy(lastData, 0, res, this.BlockBytes * fullSizedBlocksCount, lastData.Length);

            return res;
        }

        return encryptedBytes;
    }

    public byte[] Decrypt(byte[] data)
    {
        if (data.Length == 0)
        {
            return data;
        }

        this.receivedBytes += data.LongLength;

        byte[] fullBuffer = new byte[this.lastBlockBuffer.Count + data.Length];

        /* Prepend the last leftover bytes to new data. */
        Buffer.BlockCopy(this.lastBlockBuffer.ToArray(), 0, fullBuffer, 0, this.lastBlockBuffer.Count);
        Buffer.BlockCopy(data, 0, fullBuffer, this.lastBlockBuffer.Count, data.Length);

        byte[][] blocks = fullBuffer.SplitIntoBlocksOfSize(this.BlockBytes);

        int fullSizedBlocksCount = blocks.Length - 1;

        if (this.receivedBytes == this.paddedMessageLength || blocks[^1].Length < this.BlockBytes)
        {
            this.lastBlockBuffer = blocks[^1].ToList();
        }
        else
        {
            fullSizedBlocksCount = blocks.Length;
            this.lastBlockBuffer.Clear();
        }

        byte[] decryptedBytes = new byte[this.BlockBytes * fullSizedBlocksCount];

        /* Last block may be of length < BlockSize. */
        /* Process all of the BlockSize blocks. */
        for (int i = 0; i < fullSizedBlocksCount; i++)
        {
            Debug.Assert(blocks[i].Length == this.BlockBytes);

            uint[] res = blocks[i].ToUInt32Array();
            DecryptBlock(ref res, this.key);

            Buffer.BlockCopy(res, 0, decryptedBytes, i * this.BlockBytes, res.Length * sizeof(uint));
        }

        if (this.receivedBytes == this.paddedMessageLength)
        {
            byte[] lastData = this.FinishDecryption();
            byte[] res = new byte[this.BlockBytes * fullSizedBlocksCount + lastData.Length];

            Buffer.BlockCopy(decryptedBytes, 0, res, 0, decryptedBytes.Length);
            Buffer.BlockCopy(lastData, 0, res, this.BlockBytes * fullSizedBlocksCount, lastData.Length);

            return res;
        }

        if (decryptedBytes.Length >= sizeof(long) && this.messageLength == -1)
        {
            byte[] messageLengthBytes = decryptedBytes[0..sizeof(long)];

            /* Remove message length from message. */
            decryptedBytes = decryptedBytes[sizeof(long)..];

            this.messageLength = BitConverter.ToInt64(messageLengthBytes);

            this.paddedMessageLength = this.messageLength + this.BlockBytes - 1;
            this.paddedMessageLength -= (this.paddedMessageLength % this.BlockBytes);
        }

        return decryptedBytes;
    }

    private byte[] FinishEncryption()
    {
        /* Pad to block size and encrypt. */

        uint[] v = new uint[this.BlockBytes / sizeof(uint)];

        byte[] data = this.lastBlockBuffer.ToArray();

        Buffer.BlockCopy(data, 0, v, 0, data.Length);

        EncryptBlock(ref v, this.key);

        this.lastBlockBuffer.Clear();

        return v.ToByteArray();
    }

    private byte[] FinishDecryption()
    {
        /* DecryptBlock and remove padding. */

        long padLength = this.receivedBytes - sizeof(long) - this.messageLength; // sizeof(long) because of initial message length

        byte[] data = this.lastBlockBuffer.ToArray();

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

        this.receivedBytes += data.LongLength;

        byte[] fullBuffer = new byte[this.lastBlockBuffer.Count + data.Length];

        /* Prepend the last leftover bytes to new data. */
        Buffer.BlockCopy(this.lastBlockBuffer.ToArray(), 0, fullBuffer, 0, this.lastBlockBuffer.Count);
        Buffer.BlockCopy(data, 0, fullBuffer, this.lastBlockBuffer.Count, data.Length);

        byte[] leftOver = fullBuffer[(fullBuffer.Length - fullBuffer.Length % this.BlockBytes)..];

        uint[][] blocks = fullBuffer.SplitIntoUInt32BlocksOfSize(this.BlockBytes);

        int fullSizedBlocksCount;

        if (leftOver.Length == 0)
        {
            fullSizedBlocksCount = blocks.Length;
            this.lastBlockBuffer.Clear();
        }
        else
        {
            fullSizedBlocksCount = blocks.Length - 1;

            /* Save the block of length < BlockSize. */
            this.lastBlockBuffer = leftOver.ToList();
        }

        byte[] encryptedBytes = new byte[this.BlockBytes * fullSizedBlocksCount];

        /* Last block may be of length < BlockSize. */
        /* Process all of the BlockSize blocks. */
        var threads = new Thread[numThreads];

        for (int i = 0; i < fullSizedBlocksCount; i++)
        {
            int blockIndex = i;

            threads[i] = new Thread(() =>
            {
                EncryptBlock(ref blocks[blockIndex], this.key);

            });
            threads[i].Start();
        }

        for (int i = 0; i < fullSizedBlocksCount; i++)
        {
            threads[i].Join();
        }

        for (int i = 0; i < fullSizedBlocksCount; i++)
        {
            Buffer.BlockCopy(blocks[i], 0, encryptedBytes, i * this.BlockBytes, blocks[i].Length * sizeof(uint));
        }

        if (this.receivedBytes == this.messageLength)
        {
            byte[] lastData = this.FinishEncryption();
            byte[] res = new byte[this.BlockBytes * fullSizedBlocksCount + lastData.Length];

            Buffer.BlockCopy(encryptedBytes, 0, res, 0, encryptedBytes.Length);
            Buffer.BlockCopy(lastData, 0, res, this.BlockBytes * fullSizedBlocksCount, lastData.Length);

            return res;
        }

        return encryptedBytes;
    }

    public byte[] DecryptParallel(byte[] data, int numThreads)
    {
        if (data.Length == 0)
        {
            return data;
        }

        this.receivedBytes += data.LongLength;

        byte[] fullBuffer = new byte[this.lastBlockBuffer.Count + data.Length];

        /* Prepend the last leftover bytes to new data. */
        Buffer.BlockCopy(this.lastBlockBuffer.ToArray(), 0, fullBuffer, 0, this.lastBlockBuffer.Count);
        Buffer.BlockCopy(data, 0, fullBuffer, this.lastBlockBuffer.Count, data.Length);

        byte[] leftOver = fullBuffer[(fullBuffer.Length - fullBuffer.Length % this.BlockBytes)..];

        uint[][] blocks = fullBuffer.SplitIntoUInt32BlocksOfSize(this.BlockBytes);

        int fullSizedBlocksCount = blocks.Length - 1;

        if (leftOver.Length > 0)
        {
            this.lastBlockBuffer = leftOver.ToList();
            fullSizedBlocksCount = blocks.Length - 1;
        }
        else
        {
            fullSizedBlocksCount = blocks.Length;
            this.lastBlockBuffer.Clear();
        }

        if (this.receivedBytes == this.paddedMessageLength)
        {
            this.lastBlockBuffer = new List<byte>(blocks[^1].ToByteArray());
            fullSizedBlocksCount = blocks.Length - 1;
        }

        byte[] decryptedBytes = new byte[this.BlockBytes * fullSizedBlocksCount];

        /* Last block may be of length < BlockSize. */
        /* Process all of the BlockSize blocks. */
        var threads = new Thread[numThreads];

        for (int i = 0; i < fullSizedBlocksCount; i++)
        {
            int blockIndex = i;

            threads[i] = new Thread(() =>
            {
                DecryptBlock(ref blocks[blockIndex], this.key);
            });
            threads[i].Start();
        }

        for (int i = 0; i < fullSizedBlocksCount; i++)
        {
            threads[i].Join();
        }

        for (int i = 0; i < fullSizedBlocksCount; i++)
        {
            Buffer.BlockCopy(blocks[i], 0, decryptedBytes, i * this.BlockBytes, blocks[i].Length * sizeof(uint));
        }

        if (this.receivedBytes == this.paddedMessageLength)
        {
            byte[] lastData = this.FinishDecryption();
            byte[] res = new byte[this.BlockBytes * fullSizedBlocksCount + lastData.Length];

            Buffer.BlockCopy(decryptedBytes, 0, res, 0, decryptedBytes.Length);
            Buffer.BlockCopy(lastData, 0, res, this.BlockBytes * fullSizedBlocksCount, lastData.Length);

            return res;
        }

        if (this.messageLength == -1)
        {
            byte[] messageLengthBytes = decryptedBytes[0..sizeof(long)];

            /* Remove message length from message. */
            decryptedBytes = decryptedBytes[sizeof(long)..];

            this.messageLength = BitConverter.ToInt64(messageLengthBytes);

            this.paddedMessageLength = this.messageLength + this.BlockBytes - 1;
            this.paddedMessageLength -= (this.paddedMessageLength % this.BlockBytes);
        }

        return decryptedBytes;
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

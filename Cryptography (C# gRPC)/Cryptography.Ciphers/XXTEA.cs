namespace Cryptography.Ciphers;
public class XXTEA : IBlockCipher
{
    private const uint Delta = 0x9E3779B9;

    public byte[] Encrypt(byte[] data, byte[] key)
    {
        if (data.Length == 0)
        {
            return data;
        }

        return ToByteArray(Encrypt(ToUInt32Array(data), ToUInt32Array(key)));
    }

    public byte[] Decrypt(byte[] data, byte[] key)
    {
        if (data.Length == 0)
        {
            return data;
        }

        return ToByteArray(Decrypt(ToUInt32Array(data), ToUInt32Array(key)));
    }

    public void EncryptRef(ref byte[] data, byte[] key)
    {
        if (data.Length == 0)
        {
            return;
        }

        data = ToByteArray(Encrypt(ToUInt32Array(data), ToUInt32Array(key)));
    }

    public void DecryptRef(ref byte[] data, byte[] key)
    {
        if (data.Length == 0)
        {
            return;
        }

        data = ToByteArray(Decrypt(ToUInt32Array(data), ToUInt32Array(key)));
    }


    private static uint[] Encrypt(uint[] v, uint[] k)
    {
        int n = v.Length - 1;
        if (n < 1)
        {
            return v;
        }
        if (k.Length < 4)
        {
            uint[] Key = new uint[4];
            k.CopyTo(Key, 0);
            k = Key;
        }
        uint z = v[n], y = v[0], sum = 0, e;
        int p, q = 6 + 52 / (n + 1);
        while (q-- > 0)
        {
            sum += Delta;
            e = sum >> 2 & 3;
            for (p = 0; p < n; p++)
            {
                y = v[p + 1];
                z = v[p] += (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
            }
            y = v[0];
            z = v[n] += (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
        }
        return v;
    }

    private static uint[] Decrypt(uint[] v, uint[] k)
    {
        int n = v.Length - 1;
        if (n < 1)
        {
            return v;
        }
        if (k.Length < 4)
        {
            uint[] Key = new uint[4];
            k.CopyTo(Key, 0);
            k = Key;
        }
        uint z = v[n], y = v[0], sum, e;
        int p, q = 6 + 52 / (n + 1);
        sum = (uint)(q * Delta);
        while (sum != 0)
        {
            e = sum >> 2 & 3;
            for (p = n; p > 0; p--)
            {
                z = v[p - 1];
                y = v[p] -= (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
            }
            z = v[n];
            y = v[0] -= (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
            sum -= Delta;
        }
        return v;
    }

    private static byte[] ToByteArray(uint[] data)
    {
        byte[] byteArray = new byte[data.Length * sizeof(uint)];

        Buffer.BlockCopy(data, 0, byteArray, 0, data.Length * sizeof(uint));

        return byteArray;
    }

    private static uint[] ToUInt32Array(byte[] data)
    {
        uint[] uintArray = new uint[data.Length / sizeof(uint)];

        Buffer.BlockCopy(data, 0, uintArray, 0, data.Length);

        return uintArray;
    }

    public byte[] EncryptParallel(byte[] data, byte[] key, int numThreads)
    {
        byte[][] blocks = SplitIntoBlocks(data, numThreads);

        List<Thread> threads = new List<Thread>();

        for (int i = 0; i < blocks.Length; i++)
        {
            int blockIndex = i;
            Thread thread = new Thread(() => EncryptRef(ref blocks[blockIndex], key));

            thread.Start();
            threads.Add(thread);
        }

        foreach (Thread thread in threads)
        {
            thread.Join();
        }

        return JoinBlocks(blocks);
    }

    public byte[] DecryptParallel(byte[] data, byte[] key, int numThreads)
    {
        byte[][] blocks = SplitIntoBlocks(data, numThreads);

        List<Thread> threads = new List<Thread>();

        for (int i = 0; i < blocks.Length; i++)
        {
            int blockIndex = i;
            Thread thread = new Thread(() => DecryptRef(ref blocks[blockIndex], key));

            thread.Start();
            threads.Add(thread);
        }

        foreach (Thread thread in threads)
        {
            thread.Join();
        }

        return JoinBlocks(blocks);
    }

    static byte[][] SplitIntoBlocks(byte[] data, int numBlocks)
    {
        int blockSize = (int)Math.Ceiling((double)data.Length / numBlocks);
        byte[][] blocks = new byte[numBlocks][];

        for (int i = 0; i < numBlocks; i++)
        {
            int startIndex = i * blockSize;
            int length = Math.Min(blockSize, data.Length - startIndex);
            blocks[i] = new byte[length];
            Array.Copy(data, startIndex, blocks[i], 0, length);
        }

        return blocks;
    }

    public static byte[] JoinBlocks(byte[][] blocks)
    {
        int totalSize = blocks.Sum(block => block.Length);

        byte[] data = new byte[totalSize];

        int offset = 0;
        foreach (byte[] block in blocks)
        {
            Array.Copy(block, 0, data, offset, block.Length);
            offset += block.Length;
        }

        return data;
    }
}
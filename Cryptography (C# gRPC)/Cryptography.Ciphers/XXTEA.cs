#define OPTIMIZED

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

        uint[] res = ToUInt32Array(data);
        Encrypt(ref res, ToUInt32Array(key));

        return ToByteArray(res);
    }

    public byte[] Decrypt(byte[] data, byte[] key)
    {
        if (data.Length == 0)
        {
            return data;
        }

        uint[] res = ToUInt32Array(data);
        Decrypt(ref res, ToUInt32Array(key));

        return ToByteArray(res);
    }

    private static void Encrypt(ref uint[] v, uint[] k)
    {
        int n = v.Length - 1;
        if (n < 1)
        {
            return;
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
    }

    private static void Decrypt(ref uint[] v, uint[] k)
    {
        int n = v.Length - 1;
        if (n < 1)
        {
            return;
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
    }

    private static byte[] ToByteArray(uint[] data)
    {
        byte[] byteArray = new byte[data.Length * sizeof(uint)];

        Buffer.BlockCopy(data, 0, byteArray, 0, data.Length * sizeof(uint));

        return byteArray;
    }

    private static uint[] ToUInt32Array(byte[] data)
    {
        uint[] uintArray = new uint[(int)Math.Ceiling((double)data.Length / sizeof(uint))];

        Buffer.BlockCopy(data, 0, uintArray, 0, data.Length);

        return uintArray;
    }

    public static byte[] EncryptParallel(byte[] data, byte[] key, int numThreads)
    {
        uint[][] blocks = data.SplitIntoNUInt32Blocks(numThreads);

        uint[] keyUIntArray = ToUInt32Array(key);

        Thread[] threads = new Thread[numThreads];

        for (int i = 0; i < blocks.Length; i++)
        {
            int blockIndex = i;
            threads[i] = new Thread(() => Encrypt(ref blocks[blockIndex], keyUIntArray));
            threads[i].Start();
        }

        foreach (Thread thread in threads)
        {
            thread.Join();
        }

        return blocks.JoinBlocks();
    }

    public static byte[] DecryptParallel(byte[] data, byte[] key, int numThreads)
    {
        uint[][] blocks = data.SplitIntoNUInt32Blocks(numThreads);

        uint[] keyUIntArray = ToUInt32Array(key);

        Thread[] threads = new Thread[numThreads];

        for (int i = 0; i < blocks.Length; i++)
        {
            int blockIndex = i;
            threads[i] = new Thread(() => Decrypt(ref blocks[blockIndex], keyUIntArray));
            threads[i].Start();
        }

        foreach (Thread thread in threads)
        {
            thread.Join();
        }

        return blocks.JoinBlocks();
    }
}
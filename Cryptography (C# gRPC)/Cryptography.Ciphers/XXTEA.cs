using System.Threading;

namespace Cryptography.Ciphers;
public class XXTEA : IBlockCipher
{
    private const uint Delta = 0x9E3779B9;
    private readonly uint[] key;

    public XXTEA(byte[] key)
    {
        this.key = key.ToUInt32Array();
    }
    public byte[] Encrypt(byte[] data)
    {
        if (data.Length == 0)
        {
            return data;
        }

        uint[] res = data.ToUInt32Array();
        Encrypt(ref res, this.key);

        return res.ToByteArray();
    }

    public byte[] Decrypt(byte[] data)
    {
        if (data.Length == 0)
        {
            return data;
        }

        uint[] res = data.ToUInt32Array();
        Decrypt(ref res, this.key);

        return res.ToByteArray();
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
#if false
        ThreadPool.GetMaxThreads(out int workerThreads, out int completionPortThreads);
        ThreadPool.SetMaxThreads(numThreads, completionPortThreads);
#endif
        uint[][] blocks = data.SplitIntoNUInt32Blocks(numThreads);

        var threads = new Thread[numThreads];

#if false
        var countdownEvent = new CountdownEvent(blocks.Length);
#endif
        for (int i = 0; i < blocks.Length; i++)
        {
            int blockIndex = i;
            threads[i] = new Thread(() => Encrypt(ref blocks[blockIndex], this.key));
            threads[i].Start();

#if false
            ThreadPool.QueueUserWorkItem((state) =>
            {
                Encrypt(ref blocks[blockIndex], this.key);
                countdownEvent.Signal();
            });
#endif
        }

        foreach (Thread thread in threads)
        {
            thread.Join();
        }

#if false
        countdownEvent.Wait();
#endif

#if false
        Parallel.ForEach(blocks, (block) => Encrypt(ref block, this.key));
#endif
        return blocks.JoinBlocks();
    }

    public byte[] DecryptParallel(byte[] data, int numThreads)
    {
#if false
        ThreadPool.GetMaxThreads(out int workerThreads, out int completionPortThreads);
        ThreadPool.SetMaxThreads(numThreads, completionPortThreads);
#endif
        uint[][] blocks = data.SplitIntoNUInt32Blocks(numThreads);

        var threads = new Thread[numThreads];

#if false
        var countdownEvent = new CountdownEvent(blocks.Length);
#endif
        for (int i = 0; i < blocks.Length; i++)
        {
            int blockIndex = i;
            threads[i] = new Thread(() => Decrypt(ref blocks[blockIndex], this.key));
            threads[i].Start();

#if false
            ThreadPool.QueueUserWorkItem((state) =>
            {
                Decrypt(ref blocks[blockIndex], this.key);
                countdownEvent.Signal();
            });
#endif
        }

        foreach (Thread thread in threads)
        {
            thread.Join();
        }

#if false
        countdownEvent.Wait();
#endif

#if false
        Parallel.ForEach(blocks, (block) => Decrypt(ref block, this.key));
#endif
        return blocks.JoinBlocks();
    }
}

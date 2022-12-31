using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.Ciphers;
public class ByteBlockSplitter
{
    private readonly int blockSize;
    private readonly List<byte> buffer;

    public ByteBlockSplitter(int blockSize)
    {
        this.blockSize = blockSize;
        this.buffer = new List<byte>(blockSize);
    }

    public IEnumerable<byte[]> Split(byte[] data)
    {
        this.buffer.AddRange(data);

        while (this.buffer.Count >= this.blockSize)
        {
            yield return this.buffer.Take(this.blockSize).ToArray();

            this.buffer.RemoveRange(0, this.blockSize);
        }
    }

    public byte[] Flush()
    {
        byte[] leftOverData = this.buffer.ToArray();

        this.buffer.Clear();

        return leftOverData;
    }
}

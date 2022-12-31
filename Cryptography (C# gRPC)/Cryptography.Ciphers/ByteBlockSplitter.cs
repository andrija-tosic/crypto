namespace Cryptography.Ciphers;
public class ByteBlockSplitter
{
    private readonly int blockSize;
    private List<byte> lastBlockBuffer;

    public ByteBlockSplitter(int blockSize)
    {
        this.blockSize = blockSize;
        this.lastBlockBuffer = new List<byte>(blockSize);
    }

    public void PrependData(byte[] data)
    {
        this.lastBlockBuffer.InsertRange(0, data);
    }

    public IEnumerable<byte[]> EnumerateBlocks(byte[] data)
    {
        if (data.Length != 0)
        {
            byte[] fullBuffer = new byte[this.lastBlockBuffer.Count + data.Length];

            /* Prepend the last leftover bytes to new data. */
            Buffer.BlockCopy(this.lastBlockBuffer.ToArray(), 0, fullBuffer, 0, this.lastBlockBuffer.Count);
            Buffer.BlockCopy(data, 0, fullBuffer, this.lastBlockBuffer.Count, data.Length);

            byte[][] blocks = fullBuffer.SplitIntoBlocksOfSize(this.blockSize);

            for (int i = 0; i < blocks.Length - 1; i++)
            {
                yield return blocks[i];
            }

            this.lastBlockBuffer = blocks[^1].ToList();
        }
    }

    public byte[][] SplitToBlocks(byte[] data)
    {
        if (data.Length == 0)
        {
            return Array.Empty<byte[]>();
        }

        byte[] fullBuffer = new byte[this.lastBlockBuffer.Count + data.Length];

        /* Prepend the last leftover bytes to new data. */
        Buffer.BlockCopy(this.lastBlockBuffer.ToArray(), 0, fullBuffer, 0, this.lastBlockBuffer.Count);
        Buffer.BlockCopy(data, 0, fullBuffer, this.lastBlockBuffer.Count, data.Length);

        byte[][] blocks = fullBuffer.SplitIntoBlocksOfSize(this.blockSize);

        this.lastBlockBuffer = blocks[^1].ToList();

        return blocks[..^1];
    }

    public byte[] Flush()
    {
        byte[] leftOverData = this.lastBlockBuffer.ToArray();

        this.lastBlockBuffer.Clear();

        return leftOverData;
    }
}

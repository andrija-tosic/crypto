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

    public IEnumerable<Memory<byte>> SplitToBlocks(byte[] data)
    {
        if (data.Length != 0)
        {
            this.lastBlockBuffer.AddRange(data);

            ///* Prepend the last leftover bytes to new data. */

            Memory<byte>[] blocks = this.lastBlockBuffer.ToArray().SliceIntoBlocksOfSize(this.blockSize).ToArray();

            for (int i = 0; i < blocks.Length - 1; i++)
            {
                yield return blocks[i];
            }

            this.lastBlockBuffer.Clear();
            this.lastBlockBuffer.AddRange(blocks[^1].ToArray());
        }
    }

    public IEnumerable<byte[]> SplitToByteArrayBlocks(byte[] data)
    {
        if (data.Length != 0)
        {
            /* Prepend the last leftover bytes to new data. */
            this.lastBlockBuffer.AddRange(data);

            Memory<byte>[] blocks = this.lastBlockBuffer.ToArray().SliceIntoBlocksOfSize(this.blockSize).ToArray();

            for (int i = 0; i < blocks.Length - 1; i++)
            {
                yield return blocks[i].ToArray();
            }

            this.lastBlockBuffer.Clear();
            this.lastBlockBuffer.AddRange(blocks[^1].ToArray());
        }
    }

    public byte[] Flush()
    {
        byte[] leftOverData = this.lastBlockBuffer.ToArray();

        this.lastBlockBuffer.Clear();

        return leftOverData;
    }
}

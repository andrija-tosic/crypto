namespace Cryptography.Ciphers;

internal static class ArrayExtensions
{
    public static byte[][] SplitIntoBlocksOfSize(this byte[] data, int blockSize)
    {
        int numBlocks = (int)Math.Ceiling((double)data.Length / blockSize);
        byte[][] blocks = new byte[numBlocks][];
        for (int i = 0; i < numBlocks; i++)
        {
            int offset = i * blockSize;
            int remaining = data.Length - offset;
            int length = Math.Min(blockSize, remaining);
            blocks[i] = new byte[length];
            Buffer.BlockCopy(data, offset, blocks[i], 0, length);
        }

        return blocks;
    }

    public static uint[][] SplitIntoUInt32BlocksOfSize(this byte[] data, int blockSize)
    {
        int numBlocks = (int)Math.Ceiling((double)data.Length / blockSize);
        uint[][] blocks = new uint[numBlocks][];

        for (int i = 0; i < numBlocks; i++)
        {
            int offset = i * blockSize;
            int remaining = data.Length - offset;
            int length = Math.Min(blockSize, remaining);
            blocks[i] = new uint[length / sizeof(uint)];
            Buffer.BlockCopy(data, offset, blocks[i], 0, length);
        }

        return blocks;
    }

    public static byte[][] SplitIntoNBlocks(this byte[] data, int numBlocks)
    {
        int blockSize = (int)Math.Ceiling((double)data.Length / numBlocks);
        byte[][] blocks = new byte[numBlocks][];

        for (int i = 0; i < numBlocks; i++)
        {
            int offset = i * blockSize;
            int remaining = data.Length - offset;
            int length = Math.Min(blockSize, remaining);
            blocks[i] = new byte[length];
            Buffer.BlockCopy(data, offset, blocks[i], 0, length);
        }

        return blocks;
    }

    public static uint[][] SplitIntoNUInt32Blocks(this byte[] data, int numBlocks)
    {
        int blockSize = (int)Math.Ceiling((double)data.Length / numBlocks);
        uint[][] blocks = new uint[numBlocks][];

        for (int i = 0; i < numBlocks; i++)
        {
            int offset = i * blockSize;
            int remaining = data.Length - offset;
            int length = Math.Min(blockSize, remaining);
            blocks[i] = new uint[length / sizeof(uint)];
            Buffer.BlockCopy(data, offset, blocks[i], 0, length);
        }

        return blocks;
    }

    public static byte[] JoinBlocks(this byte[][] blocks)
    {
        int totalSize = blocks.Sum(block => block.Length);

        byte[] data = new byte[totalSize];

        int offset = 0;
        foreach (byte[] block in blocks)
        {
            Buffer.BlockCopy(block, 0, data, offset, block.Length);
            offset += block.Length;
        }

        return data;
    }

    public static byte[] JoinBlocks(this uint[][] blocks)
    {
        int totalSize = blocks.Sum(block => block.Length * sizeof(uint));

        byte[] data = new byte[totalSize];

        int offset = 0;
        foreach (uint[] block in blocks)
        {
            Buffer.BlockCopy(block, 0, data, offset, block.Length * sizeof(uint));
            offset += block.Length * sizeof(uint);
        }

        return data;
    }

    public static byte[] ToByteArray(this uint[] data)
    {
        byte[] byteArray = new byte[data.Length * sizeof(uint)];

        Buffer.BlockCopy(data, 0, byteArray, 0, data.Length * sizeof(uint));

        return byteArray;
    }

    public static uint[] ToUInt32Array(this byte[] data)
    {
        uint[] uintArray = new uint[(int)Math.Ceiling((double)data.Length / sizeof(uint))];

        Buffer.BlockCopy(data, 0, uintArray, 0, data.Length);

        return uintArray;
    }

}

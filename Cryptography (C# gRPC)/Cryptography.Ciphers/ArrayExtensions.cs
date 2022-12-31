namespace Cryptography.Ciphers;

internal static class ArrayExtensions
{
    public static byte[][] SplitIntoBlocksOfSize(this byte[] data, int blockBytes)
    {
        int numBlocks = (int)Math.Ceiling((double)data.Length / blockBytes);
        byte[][] blocks = new byte[numBlocks][];
        for (int i = 0; i < numBlocks; i++)
        {
            int offset = i * blockBytes;
            int remaining = data.Length - offset;
            int length = Math.Min(blockBytes, remaining);
            blocks[i] = new byte[length];
            Buffer.BlockCopy(data, offset, blocks[i], 0, length);
        }

        return blocks;
    }

    public static uint[][] SplitIntoUInt32BlocksOfSize(this byte[] data, int blockBytes)
    {
        int numBlocks = (int)Math.Ceiling((double)data.Length / blockBytes);
        uint[][] blocks = new uint[numBlocks][];

        for (int i = 0; i < numBlocks; i++)
        {
            int offset = i * blockBytes;
            int remaining = data.Length - offset;
            int length = Math.Min(blockBytes, remaining);
            blocks[i] = new uint[(int)Math.Ceiling((double)length / sizeof(uint))];
            Buffer.BlockCopy(data, offset, blocks[i], 0, length);
        }

        return blocks;
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

using System.Runtime.InteropServices;

namespace Cryptography.Ciphers;

internal static class ArrayExtensions
{
    public static IEnumerable<byte[]> SplitIntoBlocksOfSize(this byte[] data, int blockBytes)
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

            yield return blocks[i];
        }
    }

    public static Span<byte> AsByteSpan(this Span<uint> data)
    {
        return MemoryMarshal.AsBytes(data);
    }

    public static uint[] ToUInt32Array(this byte[] data)
    {
        uint[] uintArray = new uint[(int)Math.Ceiling((double)data.Length / sizeof(uint))];

        Buffer.BlockCopy(data, 0, uintArray, 0, data.Length);

        return uintArray;
    }

    public static Span<uint> AsUInt32Span(this Span<byte> data)
    {
        return MemoryMarshal.Cast<byte, uint>(data);
    }
}

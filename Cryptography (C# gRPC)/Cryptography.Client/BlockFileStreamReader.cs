using Grpc.Core;
using Google.Protobuf;

namespace Cryptography.Client;
public class BlockFileStreamReader : IDisposable
{
    private readonly Stream stream;
    private byte[] buffer;
    private int blockSize;

    public BlockFileStreamReader(string filePath, int blockSize)
    {
        stream = File.OpenRead(filePath);
        buffer = new byte[blockSize];
        this.blockSize = blockSize;
    }

    public async Task<bool> ReadBlock()
    {
        int bytesRead = await stream.ReadAsync(buffer);
        CurrentBlock = ByteString.CopyFrom(buffer, 0, bytesRead);
        return bytesRead > 0;
    }

    public void Dispose()
    {
        stream.Dispose();
        GC.SuppressFinalize(this);
    }

    public ByteString CurrentBlock { get; private set; }
    public int BlockSize
    {
        get => blockSize;
        set
        {
            Array.Resize(ref buffer, value);
            blockSize = value;
        }
    }
}

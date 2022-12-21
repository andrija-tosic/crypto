using Grpc.Core;
using Google.Protobuf;

namespace Cryptography.Client;
public class BlockStream : IAsyncStreamReader<ByteString>
{
    private readonly Stream stream;
    private byte[] buffer;
    readonly int blockSize;

    public BlockStream(Stream stream, int blockSize)
    {
        this.stream = stream;
        buffer = new byte[blockSize];
        this.blockSize = blockSize;
    }

    public async Task<bool> MoveNext(CancellationToken cancellationToken)
    {
        int count = await stream.ReadAsync(buffer, cancellationToken);
        if (count < blockSize)
        {
            Array.Resize(ref buffer, count);
        }
        Current = ByteString.CopyFrom(buffer, 0, count);
        return count > 0;
    }

    public ByteString Current { get; private set; }
}

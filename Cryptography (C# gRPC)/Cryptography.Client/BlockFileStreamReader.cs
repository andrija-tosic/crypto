using Google.Protobuf;

namespace Cryptography.Client;
public class BlockFileStreamReader : IDisposable
{
    private readonly Stream stream;
    private byte[] buffer;
    private int blockSize;

    public BlockFileStreamReader(string filePath, int blockSize)
    {
        this.stream = File.OpenRead(filePath);
        this.buffer = new byte[blockSize];
        this.blockSize = blockSize;
    }

    public async Task<bool> ReadBlock()
    {
        int bytesRead = await this.stream.ReadAsync(this.buffer);
        this.CurrentBlock = ByteString.CopyFrom(this.buffer, 0, bytesRead);
        return bytesRead > 0;
    }

    public void Dispose()
    {
        this.stream.Dispose();
        GC.SuppressFinalize(this);
    }

    public ByteString CurrentBlock { get; private set; }
    public int BlockSize
    {
        get
        {
            return this.blockSize;
        }

        set
        {
            Array.Resize(ref this.buffer, value);
            this.blockSize = value;
        }
    }

    public static string BytesToString(long byteCount)
    {
        string[] suf = { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" };

        if (byteCount == 0)
        {
            return "0" + suf[0];
        }

        long bytes = Math.Abs(byteCount);
        int place = Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
        double num = Math.Round(bytes / Math.Pow(1024, place), 1);

        return (Math.Sign(byteCount) * num).ToString() + suf[place];
    }
}

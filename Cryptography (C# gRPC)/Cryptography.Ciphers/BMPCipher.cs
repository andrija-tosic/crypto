namespace Cryptography.Ciphers;
public readonly struct BMPFileHeader
{
    private readonly byte[] header = new byte[2];
    private readonly uint sizeBytes;
    private readonly ushort reserved1, reserved2;
    private readonly uint startingAddress;
    private readonly uint dibHeaderSize;
    private readonly uint width;
    private readonly uint height;
    private readonly ushort planes, bitCount;
    private readonly uint compression;
    private readonly uint sizeImage;
    private readonly uint xPixelsPerMeter;
    private readonly uint yPixelsPerMeter;
    private readonly uint clrUsed;
    private readonly uint clrImportant;

    public BMPFileHeader()
    {
    }
}

public class BMPCipher : IDisposable
{
    private readonly OneTimePad otp;

    public BMPCipher()
    {
        this.otp = new OneTimePad();
    }

    public byte[] EncryptOneTimePad(byte[] data)
    {
        return this.otp.Encrypt(ref data);
    }

    public void DecryptOneTimePad(byte[] data, byte[] pad)
    {
        this.otp.Decrypt(ref data, pad);
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}

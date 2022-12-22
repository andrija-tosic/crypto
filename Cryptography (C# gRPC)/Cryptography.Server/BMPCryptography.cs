using System.Runtime.InteropServices;

namespace Cryptography.Server;
struct BMPFileHeader
{
    byte[] header = new byte[2];
    uint sizeBytes;
    ushort reserved1, reserved2;
    uint startingAddress;

    uint dibHeaderSize;
    uint width;
    uint height;
    ushort planes, bitCount;
    uint compression;
    uint sizeImage;
    uint xPixelsPerMeter;
    uint yPixelsPerMeter;
    uint clrUsed;
    uint clrImportant;

    public BMPFileHeader()
    {
    }
}

public class BMPCryptography : IDisposable
{
    readonly int BUF_SIZE;
    OneTimePad otp;

    public BMPCryptography(int bufSize)
    {
        BUF_SIZE = bufSize;
        otp = new OneTimePad();
    }

    public byte[] EncryptOneTimePad(byte[] data)
    {
        return otp.Encrypt(ref data);
    }
    public static void ByteArrayToStruct<T>(T header, byte[] headerBytes)
    {
        GCHandle handle = GCHandle.Alloc(headerBytes, GCHandleType.Pinned);
        Marshal.PtrToStructure(handle.AddrOfPinnedObject(), header);
        handle.Free();
    }

    public void DecryptOneTimePad(byte[] data, byte[] pad)
    {
        otp.Decrypt(ref data, pad);
    }

    public void Dispose()
    {
    }
}

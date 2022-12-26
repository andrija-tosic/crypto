namespace Cryptography.Ciphers;

public struct BMPFileHeader
{
    public const int BMPHeaderSize = 54;

    private byte[] header;
    private uint sizeBytes;
    private ushort reserved1, reserved2;
    private uint startingAddress;
    private uint dibHeaderSize;
    private uint width;
    private uint height;
    private ushort planes, bitCount;
    private uint compression;
    private uint sizeImage;
    private uint xPixelsPerMeter;
    private uint yPixelsPerMeter;
    private uint clrUsed;
    private uint clrImportant;

    /* Load BMP file header from file. */
    public static BMPFileHeader FromFile(string inFilePath)
    {
        var header = new BMPFileHeader();

        using var fileStream = new FileStream(inFilePath, FileMode.Open);
        using var binaryReader = new BinaryReader(fileStream);

        header.header = binaryReader.ReadBytes(2);
        header.sizeBytes = binaryReader.ReadUInt32();
        header.reserved1 = binaryReader.ReadUInt16();
        header.reserved2 = binaryReader.ReadUInt16();
        header.startingAddress = binaryReader.ReadUInt32();
        header.dibHeaderSize = binaryReader.ReadUInt32();
        header.width = binaryReader.ReadUInt32();
        header.height = binaryReader.ReadUInt32();
        header.planes = binaryReader.ReadUInt16();
        header.bitCount = binaryReader.ReadUInt16();
        header.compression = binaryReader.ReadUInt32();
        header.sizeImage = binaryReader.ReadUInt32();
        header.xPixelsPerMeter = binaryReader.ReadUInt32();
        header.yPixelsPerMeter = binaryReader.ReadUInt32();
        header.clrUsed = binaryReader.ReadUInt32();
        header.clrImportant = binaryReader.ReadUInt32();

        return header;
    }

    public static BMPFileHeader FromFileStream(FileStream fileStream)
    {
        var header = new BMPFileHeader();
        
        using var binaryReader = new BinaryReader(fileStream);

        header.header = binaryReader.ReadBytes(2);
        header.sizeBytes = binaryReader.ReadUInt32();
        header.reserved1 = binaryReader.ReadUInt16();
        header.reserved2 = binaryReader.ReadUInt16();
        header.startingAddress = binaryReader.ReadUInt32();
        header.dibHeaderSize = binaryReader.ReadUInt32();
        header.width = binaryReader.ReadUInt32();
        header.height = binaryReader.ReadUInt32();
        header.planes = binaryReader.ReadUInt16();
        header.bitCount = binaryReader.ReadUInt16();
        header.compression = binaryReader.ReadUInt32();
        header.sizeImage = binaryReader.ReadUInt32();
        header.xPixelsPerMeter = binaryReader.ReadUInt32();
        header.yPixelsPerMeter = binaryReader.ReadUInt32();
        header.clrUsed = binaryReader.ReadUInt32();
        header.clrImportant = binaryReader.ReadUInt32();

        return header;
    }
}

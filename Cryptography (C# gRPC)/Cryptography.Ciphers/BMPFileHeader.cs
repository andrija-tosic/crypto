namespace Cryptography.Ciphers;

public readonly struct BMPFileHeader
{
    public const int BMPHeaderSize = 54;

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

    /* Load BMP file header from file. */
    public BMPFileHeader(string inFilePath)
    {
        using var fileStream = new FileStream(inFilePath, FileMode.Open);
        using var binaryReader = new BinaryReader(fileStream);

        this.header = binaryReader.ReadBytes(2);
        this.sizeBytes = binaryReader.ReadUInt32();
        this.reserved1 = binaryReader.ReadUInt16();
        this.reserved2 = binaryReader.ReadUInt16();
        this.startingAddress = binaryReader.ReadUInt32();
        this.dibHeaderSize = binaryReader.ReadUInt32();
        this.width = binaryReader.ReadUInt32();
        this.height = binaryReader.ReadUInt32();
        this.planes = binaryReader.ReadUInt16();
        this.bitCount = binaryReader.ReadUInt16();
        this.compression = binaryReader.ReadUInt32();
        this.sizeImage = binaryReader.ReadUInt32();
        this.xPixelsPerMeter = binaryReader.ReadUInt32();
        this.yPixelsPerMeter = binaryReader.ReadUInt32();
        this.clrUsed = binaryReader.ReadUInt32();
        this.clrImportant = binaryReader.ReadUInt32();
    }

    public BMPFileHeader(FileStream fileStream)
    {
        using var binaryReader = new BinaryReader(fileStream);

        this.header = binaryReader.ReadBytes(2);
        this.sizeBytes = binaryReader.ReadUInt32();
        this.reserved1 = binaryReader.ReadUInt16();
        this.reserved2 = binaryReader.ReadUInt16();
        this.startingAddress = binaryReader.ReadUInt32();
        this.dibHeaderSize = binaryReader.ReadUInt32();
        this.width = binaryReader.ReadUInt32();
        this.height = binaryReader.ReadUInt32();
        this.planes = binaryReader.ReadUInt16();
        this.bitCount = binaryReader.ReadUInt16();
        this.compression = binaryReader.ReadUInt32();
        this.sizeImage = binaryReader.ReadUInt32();
        this.xPixelsPerMeter = binaryReader.ReadUInt32();
        this.yPixelsPerMeter = binaryReader.ReadUInt32();
        this.clrUsed = binaryReader.ReadUInt32();
        this.clrImportant = binaryReader.ReadUInt32();
    }

}

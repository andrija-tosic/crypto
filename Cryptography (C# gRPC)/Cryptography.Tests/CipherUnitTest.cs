extern alias CryptoClient;
extern alias CryptoServer;

using CryptoClient::Cryptography.Client;
using Cryptography.Tests;

namespace CryptoClient.Cryptography.Cryptography.Tests;

public class CipherUnitTest : IClassFixture<ServerFixture>
{
    private const string testFilesPath = "D:\\Desktop\\crypt\\Cryptography (C# gRPC)\\Cryptography.Tests\\Resources\\";
    private readonly ServerFixture serverFixture;

    public CipherUnitTest(ServerFixture serverFixture)
    {
        this.serverFixture = serverFixture;
    }

    [Theory]
    [InlineData(testFilesPath + "bmp_otp_example.bmp")]
    public async Task BMP_Encrypt_Decrypt_Compare_SHA1(string inFilePath)
    {
        (string encryptedFilePath, string decryptedFilePath) = GetEncryptedAndDecryptedFilePaths(inFilePath);
        string padFilePath = GetPadFilePath(inFilePath);

        await RPC.EncryptBMPFileAsync(this.serverFixture.Client, inFilePath, padFilePath, encryptedFilePath);
        await RPC.DecryptBMPFileAsync(this.serverFixture.Client, encryptedFilePath, padFilePath, decryptedFilePath);

        CryptoClient::Cryptography.SHA1HashResult sha1Before = await RPC.SHA1HashFileAsync(this.serverFixture.Client, inFilePath);
        CryptoClient::Cryptography.SHA1HashResult sha1After = await RPC.SHA1HashFileAsync(this.serverFixture.Client, decryptedFilePath);

        Assert.Equal(sha1Before, sha1After);
    }

    [Theory]
    [InlineData(testFilesPath + "fsc_example.txt", "zgptfoihmuwdrcnykejaxvsbl", "mfnbdcrhsaxyogvituewljzkp")]
    public async Task FourSquareCipher_Encrypt_Decrypt_Compare_SHA1(string inFilePath, string key1, string key2)
    {
        (string encryptedFilePath, string decryptedFilePath) = GetEncryptedAndDecryptedFilePaths(inFilePath);

        await RPC.EncryptFourSquareCipherAsync(this.serverFixture.Client, inFilePath, encryptedFilePath, key1, key2);
        await RPC.DecryptFourSquareCipherAsync(this.serverFixture.Client, encryptedFilePath, decryptedFilePath, key1, key2);

        CryptoClient::Cryptography.SHA1HashResult sha1Before = await RPC.SHA1HashFileAsync(this.serverFixture.Client, inFilePath);
        CryptoClient::Cryptography.SHA1HashResult sha1After = await RPC.SHA1HashFileAsync(this.serverFixture.Client, decryptedFilePath);

        Assert.Equal(sha1Before, sha1After);
    }

    [Theory]
    [InlineData(testFilesPath + "otp_example.jpg")]
    public async Task OneTimePad_Encrypt_Decrypt_Compare_SHA1(string inFilePath)
    {
        (string encryptedFilePath, string decryptedFilePath) = GetEncryptedAndDecryptedFilePaths(inFilePath);
        string padFilePath = GetPadFilePath(inFilePath);

        await RPC.EncryptOneTimePadAsync(this.serverFixture.Client, inFilePath, padFilePath, encryptedFilePath);
        await RPC.DecryptOneTimePadAsync(this.serverFixture.Client, encryptedFilePath, padFilePath, decryptedFilePath);

        CryptoClient::Cryptography.SHA1HashResult sha1Before = await RPC.SHA1HashFileAsync(this.serverFixture.Client, inFilePath);
        CryptoClient::Cryptography.SHA1HashResult sha1After = await RPC.SHA1HashFileAsync(this.serverFixture.Client, decryptedFilePath);

        Assert.Equal(sha1Before, sha1After);
    }

    [Theory]
    [InlineData(testFilesPath + "xxtea_example.zip", "1234567812345678")]
    public async Task XXTEA_Encrypt_Decrypt_Compare_SHA1(string inFilePath, string key)
    {
        (string encryptedFilePath, string decryptedFilePath) = GetEncryptedAndDecryptedFilePaths(inFilePath);

        await RPC.EncryptXXTEAAsync(this.serverFixture.Client, inFilePath, encryptedFilePath, key);
        await RPC.DecryptXXTEAAsync(this.serverFixture.Client, encryptedFilePath, decryptedFilePath, key);

        CryptoClient::Cryptography.SHA1HashResult sha1Before = await RPC.SHA1HashFileAsync(this.serverFixture.Client, inFilePath);
        CryptoClient::Cryptography.SHA1HashResult sha1After = await RPC.SHA1HashFileAsync(this.serverFixture.Client, decryptedFilePath);

        Assert.Equal(sha1Before, sha1After);
    }

    [Theory]
    [InlineData(testFilesPath + "xxtea_parallel_example.zip", "1234567812345678")]
    public async Task XXTEAParallel_Encrypt_Decrypt_Compare_SHA1(string inFilePath, string key)
    {
        (string encryptedFilePath, string decryptedFilePath) = GetEncryptedAndDecryptedFilePaths(inFilePath);

        await RPC.EncryptXXTEAParallelAsync(this.serverFixture.Client, inFilePath, encryptedFilePath, key);
        await RPC.DecryptXXTEAParallelAsync(this.serverFixture.Client, encryptedFilePath, decryptedFilePath, key);

        CryptoClient::Cryptography.SHA1HashResult sha1Before = await RPC.SHA1HashFileAsync(this.serverFixture.Client, inFilePath);
        CryptoClient::Cryptography.SHA1HashResult sha1After = await RPC.SHA1HashFileAsync(this.serverFixture.Client, decryptedFilePath);

        Assert.Equal(sha1Before, sha1After);
    }

    [Theory]
    [InlineData(testFilesPath + "xxtea_ofb_example.jpg", "1234567812345678", "12345678")]
    public async Task XXTEAOFB_Encrypt_Decrypt_Compare_SHA1(string inFilePath, string key, string IV)
    {
        (string encryptedFilePath, string decryptedFilePath) = GetEncryptedAndDecryptedFilePaths(inFilePath);

        await RPC.EncryptXXTEAOFBAsync(this.serverFixture.Client, inFilePath, encryptedFilePath, key, IV);
        await RPC.DecryptXXTEAOFBAsync(this.serverFixture.Client, encryptedFilePath, decryptedFilePath, key, IV);

        CryptoClient::Cryptography.SHA1HashResult sha1Before = await RPC.SHA1HashFileAsync(this.serverFixture.Client, inFilePath);
        CryptoClient::Cryptography.SHA1HashResult sha1After = await RPC.SHA1HashFileAsync(this.serverFixture.Client, decryptedFilePath);

        Assert.Equal(sha1Before, sha1After);
    }

    public static (string encryptedFilePath, string decryptedFilePath) GetEncryptedAndDecryptedFilePaths(string inFilePath)
    {
        string dirPath = new FileInfo(inFilePath).Directory.FullName;

        string fileName = Path.GetFileNameWithoutExtension(inFilePath);
        string fileExt = Path.GetExtension(inFilePath);

        string encryptedFilePath = dirPath + "/" + fileName + ".enc" + fileExt;
        string decryptedFilePath = dirPath + "/" + fileName + ".dec" + fileExt;

        return (encryptedFilePath, decryptedFilePath);
    }

    public static string GetPadFilePath(string inFilePath)
    {
        string dirPath = new FileInfo(inFilePath).Directory.FullName;
        string fileName = Path.GetFileNameWithoutExtension(inFilePath);

        return dirPath + "/" + fileName + ".pad";
    }
}

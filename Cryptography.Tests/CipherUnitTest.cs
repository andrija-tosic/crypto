extern alias CryptoClient;
extern alias CryptoServer;

using CryptoClient::Cryptography.Client;
using Cryptography.Tests;

namespace CryptoClient.Cryptography.Cryptography.Tests;

public class CipherUnitTest : IClassFixture<ServerFixture>
{
    private const string testFilesPath = "D:\\Desktop\\crypt\\Cryptography.Tests\\Resources\\";
    private readonly ServerFixture serverFixture;

    public CipherUnitTest(ServerFixture serverFixture)
    {
        this.serverFixture = serverFixture;
    }

    [Theory]
    [InlineData(testFilesPath + "bmp_otp_example.bmp")]
    public async Task BMP_Encrypt_Decrypt_Compare_SHA1(string inFilePath)
    {
        var rpcClient = new RPC(this.serverFixture.Client);

        (string encryptedFilePath, string decryptedFilePath) = GetEncryptedAndDecryptedFilePaths(inFilePath);
        string padFilePath = GetPadFilePath(inFilePath);

        await rpcClient.EncryptBMPFileAsync(inFilePath, padFilePath, encryptedFilePath);
        await rpcClient.DecryptBMPFileAsync(encryptedFilePath, padFilePath, decryptedFilePath);

        CryptoClient::Cryptography.SHA1HashResult sha1Before = await rpcClient.SHA1HashFileAsync(inFilePath);
        CryptoClient::Cryptography.SHA1HashResult sha1After = await rpcClient.SHA1HashFileAsync(decryptedFilePath);

        Assert.Equal(sha1Before, sha1After);
    }

    [Theory]
    [InlineData(testFilesPath + "fsc_example.txt", "zgptfoihmuwdrcnykejaxvsbl", "mfnbdcrhsaxyogvituewljzkp")]
    public async Task FourSquareCipher_Encrypt_Decrypt_Compare_SHA1(string inFilePath, string key1, string key2)
    {
        var rpcClient = new RPC(this.serverFixture.Client);
        
        (string encryptedFilePath, string decryptedFilePath) = GetEncryptedAndDecryptedFilePaths(inFilePath);

        await rpcClient.EncryptFourSquareCipherAsync(inFilePath, encryptedFilePath, key1, key2);
        await rpcClient.DecryptFourSquareCipherAsync(encryptedFilePath, decryptedFilePath, key1, key2);

        CryptoClient::Cryptography.SHA1HashResult sha1Before = await rpcClient.SHA1HashFileAsync(inFilePath);
        CryptoClient::Cryptography.SHA1HashResult sha1After = await rpcClient.SHA1HashFileAsync(decryptedFilePath);

        Assert.Equal(sha1Before, sha1After);
    }

    [Theory]
    [InlineData(testFilesPath + "otp_example.jpg")]
    public async Task OneTimePad_Encrypt_Decrypt_Compare_SHA1(string inFilePath)
    {
        var rpcClient = new RPC(this.serverFixture.Client);
        
        (string encryptedFilePath, string decryptedFilePath) = GetEncryptedAndDecryptedFilePaths(inFilePath);
        string padFilePath = GetPadFilePath(inFilePath);

        await rpcClient.EncryptOneTimePadAsync(inFilePath, padFilePath, encryptedFilePath);
        await rpcClient.DecryptOneTimePadAsync(encryptedFilePath, padFilePath, decryptedFilePath);

        CryptoClient::Cryptography.SHA1HashResult sha1Before = await rpcClient.SHA1HashFileAsync(inFilePath);
        CryptoClient::Cryptography.SHA1HashResult sha1After = await rpcClient.SHA1HashFileAsync(decryptedFilePath);

        Assert.Equal(sha1Before, sha1After);
    }

    [Theory]
    [InlineData(testFilesPath + "xxtea_example.jpg", "1234567812345678")]
    public async Task XXTEA_Encrypt_Decrypt_Compare_SHA1(string inFilePath, string key)
    {
        var rpcClient = new RPC(this.serverFixture.Client);
        
        (string encryptedFilePath, string decryptedFilePath) = GetEncryptedAndDecryptedFilePaths(inFilePath);

        await rpcClient.EncryptXXTEAAsync(inFilePath, encryptedFilePath, key);
        await rpcClient.DecryptXXTEAAsync(encryptedFilePath, decryptedFilePath, key);

        CryptoClient::Cryptography.SHA1HashResult sha1Before = await rpcClient.SHA1HashFileAsync(inFilePath);
        CryptoClient::Cryptography.SHA1HashResult sha1After = await rpcClient.SHA1HashFileAsync(decryptedFilePath);

        Assert.Equal(sha1Before, sha1After);
    }

    [Theory]
    [InlineData(testFilesPath + "xxtea_parallel_example.zip", "1234567812345678")]
    public async Task XXTEAParallel_Encrypt_Decrypt_Compare_SHA1(string inFilePath, string key)
    {
        var rpcClient = new RPC(this.serverFixture.Client);
        
        (string encryptedFilePath, string decryptedFilePath) = GetEncryptedAndDecryptedFilePaths(inFilePath);

        await rpcClient.EncryptXXTEAParallelAsync(inFilePath, encryptedFilePath, key);
        await rpcClient.DecryptXXTEAParallelAsync(encryptedFilePath, decryptedFilePath, key);

        CryptoClient::Cryptography.SHA1HashResult sha1Before = await rpcClient.SHA1HashFileAsync(inFilePath);
        CryptoClient::Cryptography.SHA1HashResult sha1After = await rpcClient.SHA1HashFileAsync(decryptedFilePath);

        Assert.Equal(sha1Before, sha1After);
    }

    [Theory]
    [InlineData(testFilesPath + "xxtea_ofb_example.jpg", "1234567812345678", "12345678")]
    public async Task XXTEAOFB_Encrypt_Decrypt_Compare_SHA1(string inFilePath, string key, string IV)
    {
        var rpcClient = new RPC(this.serverFixture.Client);

        (string encryptedFilePath, string decryptedFilePath) = GetEncryptedAndDecryptedFilePaths(inFilePath);

        await rpcClient.EncryptXXTEAOFBAsync(inFilePath, encryptedFilePath, key, IV);
        await rpcClient.DecryptXXTEAOFBAsync(encryptedFilePath, decryptedFilePath, key, IV);

        CryptoClient::Cryptography.SHA1HashResult sha1Before = await rpcClient.SHA1HashFileAsync(inFilePath);
        CryptoClient::Cryptography.SHA1HashResult sha1After = await rpcClient.SHA1HashFileAsync(decryptedFilePath);

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

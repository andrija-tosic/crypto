using Cryptography;
using Cryptography.Client;
using Grpc.Net.Client;
using System.Diagnostics;

var channel = GrpcChannel.ForAddress($"http://localhost:5150", new GrpcChannelOptions
{
    MaxReceiveMessageSize = 16 * 1024 * 1024,
});

Cryptography.Cryptography.CryptographyClient client = new(channel);

string workingDirectory = Environment.CurrentDirectory;
string projectDirectory = Directory.GetParent(workingDirectory).Parent.Parent.FullName;

string resourcesPath = projectDirectory + "/Resources/";

Directory.CreateDirectory(resourcesPath + "Results");

var dirInfo = new DirectoryInfo(resourcesPath + "Results/");

foreach (FileInfo file in dirInfo.GetFiles())
{
    file.Delete();
}

var stopwatch = Stopwatch.StartNew();

var rpcClient = new RPC(client);

long fileSize = new FileInfo(resourcesPath + "xxtea_parallel_example.zip").Length;
Console.Write($"Hashing {BlockFileStreamReader.HumanReadableFileSize(fileSize)} file... ");
SHA1HashResult sha1Result = await rpcClient.SHA1HashFileAsync(resourcesPath + "xxtea_parallel_example.zip");

Console.WriteLine(sha1Result.Hash);
Console.WriteLine($"SHA1HashFileAsync done [{stopwatch.ElapsedMilliseconds} ms]");
stopwatch.Restart();

fileSize = new FileInfo(resourcesPath + "bmp_otp_example.bmp").Length;
Console.Write($"Hashing {BlockFileStreamReader.HumanReadableFileSize(fileSize)} file... ");
sha1Result = await rpcClient.SHA1HashFileAsync(resourcesPath + "bmp_otp_example.bmp");

Console.WriteLine(sha1Result.Hash);
Console.WriteLine($"SHA1HashFileAsync done [{stopwatch.ElapsedMilliseconds} ms]");
stopwatch.Restart();

await rpcClient.EncryptDecryptAndCheckSHA1HashAsync(Cipher.BMP, resourcesPath + "bmp_otp_example.bmp");
await rpcClient.EncryptDecryptAndCheckSHA1HashAsync(Cipher.OneTimePad, resourcesPath + "otp_example.jpg");
await rpcClient.EncryptDecryptAndCheckSHA1HashAsync(Cipher.FourSquareCipher,
    resourcesPath + "fsc_example.txt",
    "zgptfoihmuwdrcnykejaxvsbl",
    "mfnbdcrhsaxyogvituewljzkp");
await rpcClient.EncryptDecryptAndCheckSHA1HashAsync(Cipher.XXTEA, resourcesPath + "xxtea_example.jpg", "1234567812345678");
await rpcClient.EncryptDecryptAndCheckSHA1HashAsync(Cipher.XXTEAParallel, resourcesPath + "xxtea_parallel_example.zip", "1234567812345678");
await rpcClient.EncryptDecryptAndCheckSHA1HashAsync(Cipher.OFBBlockCipher, resourcesPath + "xxtea_ofb_example.jpg", "1234567812345678", "12345678");

await channel.ShutdownAsync();

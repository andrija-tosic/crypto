
using Cryptography;
using Cryptography.Client;
using Grpc.Net.Client;
using System.Diagnostics;

var channel = GrpcChannel.ForAddress($"http://localhost:5000", new GrpcChannelOptions
{
    MaxReceiveMessageSize = 16 * 1024 * 1024,
});

Cryptography.Cryptography.CryptographyClient client = new(channel);

string resourcesPath = "D:\\Desktop\\crypt\\Cryptography (C# gRPC)\\Cryptography.Client\\Resources\\";

var stopwatch = Stopwatch.StartNew();

SHA1HashResult sha1Result = await RPC.SHA1HashFileAsync(client, resourcesPath + "xxtea_parallel_example.zip");

Console.WriteLine(sha1Result.Hash);
Console.WriteLine($"SHA1HashFileAsync done [{stopwatch.ElapsedMilliseconds} ms]");
stopwatch.Restart();

sha1Result = await RPC.SHA1HashFileAsync(client, resourcesPath + "bmp_otp_example.bmp");

Console.WriteLine(sha1Result.Hash);
Console.WriteLine($"SHA1HashFileAsync done [{stopwatch.ElapsedMilliseconds} ms]");
stopwatch.Restart();

await RPC.EncryptDecryptAndCheckSHA1Hash(Cipher.BMP, client, resourcesPath + "bmp_otp_example.bmp", "", "");
await RPC.EncryptDecryptAndCheckSHA1Hash(Cipher.OneTimePad, client, resourcesPath + "otp_example.jpg", "", "");
await RPC.EncryptDecryptAndCheckSHA1Hash(Cipher.FourSquareCipher,
    client,
    resourcesPath + "fsc_example.txt",
    "zgptfoihmuwdrcnykejaxvsbl",
    "mfnbdcrhsaxyogvituewljzkp");
await RPC.EncryptDecryptAndCheckSHA1Hash(Cipher.XXTEA, client, resourcesPath + "xxtea_example.zip", "1234567812345678", "");
await RPC.EncryptDecryptAndCheckSHA1Hash(Cipher.XXTEAParallel, client, resourcesPath + "xxtea_parallel_example.zip", "1234567812345678", "");
await RPC.EncryptDecryptAndCheckSHA1Hash(Cipher.OFBBlockCipher, client, resourcesPath + "xxtea_ofb_example.jpg", "1234567812345678", "12345678");

await channel.ShutdownAsync();

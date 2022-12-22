using Cryptography.Client;
using Grpc.Net.Client;

GrpcChannel channel = GrpcChannel.ForAddress("http://localhost:5000");

var client = new Cryptography.Cryptography.CryptographyClient(channel);

string resourcesPath = "D:\\Desktop\\crypt\\Cryptography (C# gRPC)\\Cryptography.Client\\Resources\\";

var sha1Result = await RPC.SHA1HashFileAsync(client, resourcesPath + "bmp_otp_example.bmp");
Console.WriteLine(sha1Result.Hash);

//await RPC.EncryptBMPFileAsync(client,
//    resourcesPath + "bmp_otp_example.bmp",
//    resourcesPath + "bmp_otp_example.pad",
//    resourcesPath + "bmp_otp_example.enc.bmp");

//await RPC.DecryptBMPFileAsync(client,
//    resourcesPath + "bmp_otp_example.enc.bmp",
//    resourcesPath + "bmp_otp_example.pad",
//    resourcesPath + "bmp_otp_example.dec.bmp"
//    );

//await RPC.EncryptOneTimePadAsync(client,
//    resourcesPath + "otp_example.jpg",
//    resourcesPath + "otp_example.pad",
//    resourcesPath + "otp_example.enc.jpg"
//);

//await RPC.DecryptOneTimePadAsync(client,
//    resourcesPath + "otp_example.enc.jpg",
//    resourcesPath + "otp_example.pad",
//    resourcesPath + "otp_example.dec.jpg"
//);

await RPC.EncryptFourSquareCipherAsync(client,
    resourcesPath + "fsc_example.txt",
    resourcesPath + "fsc_example.enc.txt",
    "zgptfoihmuwdrcnykeqaxvsbl",
    "mfnbdcrhsaxyogvituewlqzkp");


await RPC.DecryptFourSquareCipherAsync(client,
    resourcesPath + "fsc_example.enc.txt",
    resourcesPath + "fsc_example.dec.txt",
    "zgptfoihmuwdrcnykeqaxvsbl",
    "mfnbdcrhsaxyogvituewlqzkp");

await channel.ShutdownAsync();

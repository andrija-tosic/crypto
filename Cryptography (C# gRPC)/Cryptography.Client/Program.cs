using Cryptography.Client;
using Grpc.Net.Client;

GrpcChannel channel = GrpcChannel.ForAddress("http://localhost:5000");

var client = new Cryptography.Cryptography.CryptographyClient(channel);

string resourcesPath = "D:\\Desktop\\crypt\\Cryptography (C# gRPC)\\Cryptography.Client\\Resources\\";

#if true

var sha1Result = await RPC.SHA1HashFileAsync(client, resourcesPath + "bmp_otp_example.bmp");
Console.WriteLine(sha1Result.Hash);


await RPC.EncryptBMPFileAsync(client,
    resourcesPath + "bmp_otp_example.bmp",
    resourcesPath + "bmp_otp_example.pad",
    resourcesPath + "bmp_otp_example.enc.bmp");

await RPC.DecryptBMPFileAsync(client,
    resourcesPath + "bmp_otp_example.enc.bmp",
    resourcesPath + "bmp_otp_example.pad",
    resourcesPath + "bmp_otp_example.dec.bmp"
    );

await RPC.EncryptOneTimePadAsync(client,
    resourcesPath + "otp_example.jpg",
    resourcesPath + "otp_example.pad",
    resourcesPath + "otp_example.enc.jpg"
);

await RPC.DecryptOneTimePadAsync(client,
    resourcesPath + "otp_example.enc.jpg",
    resourcesPath + "otp_example.pad",
    resourcesPath + "otp_example.dec.jpg"
);

await RPC.EncryptFourSquareCipherAsync(client,
    resourcesPath + "fsc_example.txt",
    resourcesPath + "fsc_example.enc.txt",
    "NCDYRJETUPXOFGBMHIWSVKAZL",
    "YXNEMKDIJFGRTWOABUSCHLZVP");


await RPC.DecryptFourSquareCipherAsync(client,
    resourcesPath + "fsc_example.enc.txt",
    resourcesPath + "fsc_example.dec.txt",
    "NCDYRJETUPXOFGBMHIWSVKAZL",
    "YXNEMKDIJFGRTWOABUSCHLZVP");


await RPC.EncryptXXTEAAsync(client,
    resourcesPath + "xxtea_example.jpg",
    resourcesPath + "xxtea_example.enc.jpg",
    "12345678",
    false
    );

await RPC.DecryptXXTEAAsync(client,
    resourcesPath + "xxtea_example.enc.jpg",
    resourcesPath + "xxtea_example.dec.jpg",
    "12345678",
    false
    );

await RPC.EncryptXXTEAOFBAsync(client,
    resourcesPath + "xxtea_ofb_example.jpg",
    resourcesPath + "xxtea_ofb_example.enc.jpg",
    "12345678",
    "12345678"
    );

await RPC.DecryptXXTEAOFBAsync(client,
    resourcesPath + "xxtea_ofb_example.enc.jpg",
    resourcesPath + "xxtea_ofb_example.dec.jpg",
    "12345678",
    "12345678"
    );


await RPC.EncryptXXTEAAsync(client,
    resourcesPath + "xxtea_example.jpg",
    resourcesPath + "xxtea_example.enc.jpg",
    "12345678",
    true
    );

await RPC.DecryptXXTEAAsync(client,
    resourcesPath + "xxtea_example.enc.jpg",
    resourcesPath + "xxtea_example.dec.jpg",
    "12345678",
    true
    );

#endif

await channel.ShutdownAsync();

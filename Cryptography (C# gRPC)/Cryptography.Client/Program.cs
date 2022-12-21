using Cryptography.Client;
using Grpc.Net.Client;

GrpcChannel channel = GrpcChannel.ForAddress("http://localhost:5000");

var client = new Cryptography.Cryptography.CryptographyClient(channel);

var sha1Result = await RPC.SHA1HashFileAsync(client, "D:\\Desktop\\sve najbolje.jpeg");

Console.WriteLine(sha1Result.Hash);

await channel.ShutdownAsync();

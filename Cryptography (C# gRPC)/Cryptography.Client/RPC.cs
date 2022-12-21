using Grpc.Core;
namespace Cryptography.Client;

class RPC
{
    public static async Task<SHA1HashResult> SHA1HashFileAsync(Cryptography.CryptographyClient client, string filePath)
    {
        using var fileStream = File.OpenRead(filePath);

        long fileSize = new FileInfo(filePath).Length;

        var blockStream = new BlockStream(fileStream, (int)Math.Min(fileSize, 4096));

        var call = client.ComputeSHA1Hash();

        while (await blockStream.MoveNext())
        {
            await call.RequestStream.WriteAsync(new SHA1BytesInput { Bytes = blockStream.Current });
        }

        await call.RequestStream.CompleteAsync();

        var response = await call;

        return response;
    }
}

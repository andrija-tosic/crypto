using Grpc.Core;

namespace Cryptography.Server.Services
{
    public class CryptographyService : Cryptography.CryptographyBase
    {
        public override async Task<SHA1HashResult> ComputeSHA1Hash(IAsyncStreamReader<SHA1BytesInput> requestStream, ServerCallContext context)
        {
            using var sha1 = new SHA1();

            while (await requestStream.MoveNext())
            {
                sha1.ProcessBuffer(requestStream.Current.Bytes.ToByteArray());
            }

            return new SHA1HashResult { Hash = sha1.HashHexString };
        }
    }
}

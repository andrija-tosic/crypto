using Google.Protobuf;
using Grpc.Core;
using System.Text;

namespace Cryptography.Server.Services;

public class CryptographyService : Cryptography.CryptographyBase
{
    readonly int BUF_SIZE = 4096;
    public override async Task<SHA1HashResult> ComputeSHA1Hash(IAsyncStreamReader<ByteArray> requestStream, ServerCallContext context)
    {
        using var sha1 = new SHA1();

        while (await requestStream.MoveNext())
        {
            sha1.ProcessBuffer(requestStream.Current.Bytes.ToByteArray());
        }

        return new SHA1HashResult { Hash = sha1.HashHexString };
    }

    public override async Task EncryptBMP(IAsyncStreamReader<ByteArray> requestStream, IServerStreamWriter<OneTimePadResult> responseStream, ServerCallContext context)
    {
        using var BMPCryptography = new BMPCryptography(BUF_SIZE);

        /* Skip encrypting BMP header. */

        await requestStream.MoveNext();

        var headerBytes = requestStream.Current.Bytes.ToByteArray();

        var headerResult = new OneTimePadResult
        {
            EncrpytedBytes = ByteString.CopyFrom(headerBytes),
            Pad = ByteString.CopyFrom(new byte[headerBytes.Length])
        };

        await responseStream.WriteAsync(headerResult);

        while (await requestStream.MoveNext())
        {
            byte[] toEncrypt = requestStream.Current.Bytes.ToByteArray();
            byte[] pad = BMPCryptography.EncryptOneTimePad(toEncrypt);

            var res = new OneTimePadResult
            {
                EncrpytedBytes = ByteString.CopyFrom(toEncrypt),
                Pad = ByteString.CopyFrom(pad)
            };

            await responseStream.WriteAsync(res);
        }
    }

    public override async Task DecryptBMP(IAsyncStreamReader<OneTimePadResult> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        using var BMPCryptography = new BMPCryptography(BUF_SIZE);

        /* Skip decrypting BMP header. */

        await requestStream.MoveNext();

        var headerBytes = requestStream.Current.EncrpytedBytes.ToByteArray();

        var headerResult = new ByteArray
        {
            Bytes = ByteString.CopyFrom(headerBytes)
        };

        await responseStream.WriteAsync(headerResult);

        while (await requestStream.MoveNext())
        {
            byte[] toDecrypt = requestStream.Current.EncrpytedBytes.ToByteArray();
            byte[] padToDecryptWith = requestStream.Current.Pad.ToByteArray();


            BMPCryptography.DecryptOneTimePad(toDecrypt, padToDecryptWith);

            var res = new ByteArray
            {
                Bytes = ByteString.CopyFrom(toDecrypt)
            };

            await responseStream.WriteAsync(res);
        }
    }

    public override async Task EncryptOneTimePad(IAsyncStreamReader<ByteArray> requestStream, IServerStreamWriter<OneTimePadResult> responseStream, ServerCallContext context)
    {
        var otp = new OneTimePad();

        while (await requestStream.MoveNext())
        {
            byte[] toEncrypt = requestStream.Current.Bytes.ToByteArray();
            byte[] pad = otp.Encrypt(ref toEncrypt);

            var res = new OneTimePadResult
            {
                EncrpytedBytes = ByteString.CopyFrom(toEncrypt),
                Pad = ByteString.CopyFrom(pad)
            };

            await responseStream.WriteAsync(res);
        }
    }

    public override async Task DecryptOneTimePad(IAsyncStreamReader<OneTimePadResult> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        var otp = new OneTimePad();

        while (await requestStream.MoveNext())
        {
            byte[] toDecrypt = requestStream.Current.EncrpytedBytes.ToByteArray();
            byte[] padToDecryptWith = requestStream.Current.Pad.ToByteArray();

            otp.Decrypt(ref toDecrypt, padToDecryptWith);

            var res = new ByteArray
            {
                Bytes = ByteString.CopyFrom(toDecrypt)
            };

            await responseStream.WriteAsync(res);
        }
    }

    public override async Task EncryptFourSquareCipher(IAsyncStreamReader<FourSquareCipherRequest> requestStream, IServerStreamWriter<FourSquareCipherResponse> responseStream, ServerCallContext context)
    {
        await requestStream.MoveNext();

        string key1 = requestStream.Current.Key1;
        string key2 = requestStream.Current.Key2;

        var fsc = new FourSquareCipher(key1, key2);

        do
        {
            var encryptedText = fsc.EncryptText(requestStream.Current.Text);

            var res = new FourSquareCipherResponse
            {
                Text = encryptedText
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());
    }

    public override async Task DecryptFourSquareCipher(IAsyncStreamReader<FourSquareCipherRequest> requestStream, IServerStreamWriter<FourSquareCipherResponse> responseStream, ServerCallContext context)
    {
        await requestStream.MoveNext();

        string key1 = requestStream.Current.Key1;
        string key2 = requestStream.Current.Key2;

        var fsc = new FourSquareCipher(key1, key2);

        do
        {
            string decryptedText = fsc.DecryptText(requestStream.Current.Text);

            var res = new FourSquareCipherResponse
            {
                Text = decryptedText
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());
    }

    public override async Task EncryptXXTEA(IAsyncStreamReader<XXTEARequest> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        await requestStream.MoveNext();

        byte[] key = Encoding.ASCII.GetBytes(requestStream.Current.Key);

        var xxtea = new XXTEA();

        do
        {
            byte[] toEncrypt = requestStream.Current.Bytes.ToByteArray();
            byte[] encryptedBytes = xxtea.Encrypt(toEncrypt, key);

            var res = new ByteArray
            {
                Bytes = ByteString.CopyFrom(encryptedBytes)
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());

    }

    public override async Task DecryptXXTEA(IAsyncStreamReader<XXTEARequest> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        await requestStream.MoveNext();

        byte[] key = Encoding.ASCII.GetBytes(requestStream.Current.Key);

        var xxtea = new XXTEA();

        do
        {
            byte[] toEncrypt = requestStream.Current.Bytes.ToByteArray();
            byte[] encryptedBytes = xxtea.Encrypt(toEncrypt, key);

            var res = new ByteArray
            {
                Bytes = ByteString.CopyFrom(encryptedBytes)
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());
    }

    public override async Task EncryptXXTEAOFB(IAsyncStreamReader<XXTEAOFBRequest> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        await requestStream.MoveNext();

        byte[] key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
        byte[] IV = requestStream.Current.IV.ToByteArray();

        using var xxteaOfb = new OFBBlockCipher(new XXTEA(), key, IV);

        do
        {
            byte[] toEncrypt = requestStream.Current.Bytes.ToByteArray();
            byte[] encryptedBytes = xxteaOfb.Encrypt(toEncrypt);

            var res = new ByteArray
            {
                Bytes = ByteString.CopyFrom(encryptedBytes)
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());
    }

    public override async Task DecryptXXTEAOFB(IAsyncStreamReader<XXTEAOFBRequest> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        await requestStream.MoveNext();

        byte[] key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
        byte[] IV = requestStream.Current.IV.ToByteArray();

        using var xxteaOfb = new OFBBlockCipher(new XXTEA(), key, IV);

        do
        {
            byte[] toDecrypt = requestStream.Current.Bytes.ToByteArray();
            byte[] encryptedBytes = xxteaOfb.Decrypt(toDecrypt);

            var res = new ByteArray
            {
                Bytes = ByteString.CopyFrom(encryptedBytes)
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());
    }

    public override async Task EncryptXXTEAParallel(IAsyncStreamReader<XXTEARequest> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        await requestStream.MoveNext();

        byte[] key = Encoding.ASCII.GetBytes(requestStream.Current.Key);

        var xxtea = new XXTEA();

        do
        {
            byte[] toEncrypt = requestStream.Current.Bytes.ToByteArray();
            byte[] encryptedBytes = xxtea.EncryptParallel(toEncrypt, key, 16);

            var res = new ByteArray
            {
                Bytes = ByteString.CopyFrom(encryptedBytes)
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());

    }

    public override async Task DecryptXXTEAParallel(IAsyncStreamReader<XXTEARequest> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        await requestStream.MoveNext();

        byte[] key = Encoding.ASCII.GetBytes(requestStream.Current.Key);

        var xxtea = new XXTEA();

        do
        {
            byte[] toDecrypt = requestStream.Current.Bytes.ToByteArray();
            byte[] decryptedBytes = xxtea.DecryptParallel(toDecrypt, key, 16);

            var res = new ByteArray
            {
                Bytes = ByteString.CopyFrom(decryptedBytes)
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());

    }
}

using Cryptography.Ciphers;
using Google.Protobuf;
using Grpc.Core;
using System.Diagnostics;
using System.Text;

namespace Cryptography.Server.Services;

public class CryptographyService : Cryptography.CryptographyBase
{
    public const int BlockSize = 1024 * 1024;
    public override async Task<SHA1HashResult> ComputeSHA1Hash(IAsyncStreamReader<ByteArray> requestStream, ServerCallContext context)
    {
        using SHA1 sha1 = new();

        while (await requestStream.MoveNext())
        {
            sha1.ProcessBuffer(requestStream.Current.Bytes.ToByteArray());
        }

        sha1.Finish();

        return new SHA1HashResult { Hash = sha1.HashHexString };
    }

    public override async Task EncryptOneTimePad(IAsyncStreamReader<ByteArray> requestStream, IServerStreamWriter<OneTimePadResult> responseStream, ServerCallContext context)
    {
        while (await requestStream.MoveNext())
        {
            byte[] toEncrypt = requestStream.Current.Bytes.ToByteArray();
            byte[] pad = OneTimePad.Encrypt(ref toEncrypt);

            OneTimePadResult res = new()
            {
                EncrpytedBytes = ByteString.CopyFrom(toEncrypt),
                Pad = ByteString.CopyFrom(pad)
            };

            await responseStream.WriteAsync(res);
        }
    }

    public override async Task DecryptOneTimePad(IAsyncStreamReader<OneTimePadResult> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        while (await requestStream.MoveNext())
        {
            byte[] toDecrypt = requestStream.Current.EncrpytedBytes.ToByteArray();
            byte[] padToDecryptWith = requestStream.Current.Pad.ToByteArray();

            OneTimePad.Decrypt(ref toDecrypt, padToDecryptWith);

            Debug.Assert(toDecrypt.Length == padToDecryptWith.Length);

            ByteArray res = new()
            {
                Bytes = ByteString.CopyFrom(toDecrypt)
            };

            await responseStream.WriteAsync(res);
        }
    }

    public override async Task EncryptFourSquareCipher(IAsyncStreamReader<FourSquareCipherRequest> requestStream, IServerStreamWriter<FourSquareCipherResponse> responseStream, ServerCallContext context)
    {
        _ = await requestStream.MoveNext();

        string key1 = requestStream.Current.Key1;
        string key2 = requestStream.Current.Key2;

        FourSquareCipher fsc = new(key1, key2);

        do
        {
            string encryptedText = fsc.EncryptText(requestStream.Current.Text);

            FourSquareCipherResponse res = new()
            {
                Text = encryptedText
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());
    }

    public override async Task DecryptFourSquareCipher(IAsyncStreamReader<FourSquareCipherRequest> requestStream, IServerStreamWriter<FourSquareCipherResponse> responseStream, ServerCallContext context)
    {
        _ = await requestStream.MoveNext();

        string key1 = requestStream.Current.Key1;
        string key2 = requestStream.Current.Key2;

        FourSquareCipher fsc = new(key1, key2);

        do
        {
            string decryptedText = fsc.DecryptText(requestStream.Current.Text);

            FourSquareCipherResponse res = new()
            {
                Text = decryptedText
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());
    }

    public override async Task EncryptXXTEA(IAsyncStreamReader<XXTEARequest> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        _ = await requestStream.MoveNext();

        byte[] key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
        long messageLength = requestStream.Current.MessageLength;
        XXTEA xxtea = new(key, messageLength, BlockSize);

        do
        {
            byte[] toEncrypt = requestStream.Current.Bytes.ToByteArray();
            byte[] encryptedBytes = xxtea.Encrypt(toEncrypt);

            ByteArray res = new()
            {
                Bytes = ByteString.CopyFrom(encryptedBytes)
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());

        byte[] last = xxtea.FinishEncryption();

        ByteArray lastByteArray = new()
        {
            Bytes = ByteString.CopyFrom(last)
        };

        await responseStream.WriteAsync(lastByteArray);
    }

    public override async Task DecryptXXTEA(IAsyncStreamReader<XXTEARequest> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        _ = await requestStream.MoveNext();

        byte[] key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
        XXTEA xxtea = new(key, BlockSize);

        do
        {
            byte[] toDecrypt = requestStream.Current.Bytes.ToByteArray();
            byte[] decryptedBytes = xxtea.Decrypt(toDecrypt);

            ByteArray res = new()
            {
                Bytes = ByteString.CopyFrom(decryptedBytes)
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());

        byte[] last = xxtea.FinishDecryption();

        ByteArray lastByteArray = new()
        {
            Bytes = ByteString.CopyFrom(last)
        };

        await responseStream.WriteAsync(lastByteArray);

    }

    public override async Task EncryptXXTEAParallel(IAsyncStreamReader<XXTEAParallelRequest> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        _ = await requestStream.MoveNext();

        byte[] key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
        int threadCount = requestStream.Current.ThreadCount;

        long messageLength = requestStream.Current.MessageLength;
        XXTEA xxtea = new(key, messageLength, BlockSize);

        do
        {
            byte[] toEncrypt = requestStream.Current.Bytes.ToByteArray();
            byte[] encryptedBytes = xxtea.EncryptParallel(toEncrypt, threadCount);

            ByteArray res = new()
            {
                Bytes = ByteString.CopyFrom(encryptedBytes)
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());

        byte[] last = xxtea.FinishEncryption();

        ByteArray lastByteArray = new()
        {
            Bytes = ByteString.CopyFrom(last)
        };

        await responseStream.WriteAsync(lastByteArray);
    }

    public override async Task DecryptXXTEAParallel(IAsyncStreamReader<XXTEAParallelRequest> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        _ = await requestStream.MoveNext();

        byte[] key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
        int threadCount = requestStream.Current.ThreadCount;

        XXTEA xxtea = new(key, BlockSize);

        do
        {
            byte[] toDecrypt = requestStream.Current.Bytes.ToByteArray();
            byte[] decryptedBytes = xxtea.DecryptParallel(toDecrypt, threadCount);

            ByteArray res = new()
            {
                Bytes = ByteString.CopyFrom(decryptedBytes)
            };

            await responseStream.WriteAsync(res);
        } while (await requestStream.MoveNext());

        byte[] last = xxtea.FinishDecryption();

        ByteArray lastByteArray = new()
        {
            Bytes = ByteString.CopyFrom(last)
        };

        await responseStream.WriteAsync(lastByteArray);
    }

    public override async Task EncryptXXTEAOFB(IAsyncStreamReader<XXTEAOFBRequest> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        _ = await requestStream.MoveNext();

        byte[] key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
        byte[] IV = requestStream.Current.IV.ToByteArray();

        using OFBBlockCipher xxteaOfb = new(new XXTEA(key, IV.Length), IV);

        do
        {
            byte[] toEncrypt = requestStream.Current.Bytes.ToByteArray();

            foreach (byte[] encryptedBlock in xxteaOfb.Encrypt(toEncrypt))
            {
                ByteArray res = new()
                {
                    Bytes = ByteString.CopyFrom(encryptedBlock)
                };

                await responseStream.WriteAsync(res);
            }
        } while (await requestStream.MoveNext());

        byte[] final = xxteaOfb.Finish();

        ByteArray finalBytes = new()
        {
            Bytes = ByteString.CopyFrom(final)
        };

        await responseStream.WriteAsync(finalBytes);
    }

    public override async Task DecryptXXTEAOFB(IAsyncStreamReader<XXTEAOFBRequest> requestStream, IServerStreamWriter<ByteArray> responseStream, ServerCallContext context)
    {
        _ = await requestStream.MoveNext();

        byte[] key = Encoding.ASCII.GetBytes(requestStream.Current.Key);
        byte[] IV = requestStream.Current.IV.ToByteArray();

        using OFBBlockCipher xxteaOfb = new(new XXTEA(key, IV.Length), IV);

        do
        {
            byte[] toDecrypt = requestStream.Current.Bytes.ToByteArray();

            foreach (byte[] encryptedBlock in xxteaOfb.Decrypt(toDecrypt))
            {
                ByteArray res = new()
                {
                    Bytes = ByteString.CopyFrom(encryptedBlock)
                };

                await responseStream.WriteAsync(res);
            }
        } while (await requestStream.MoveNext());

        byte[] final = xxteaOfb.Finish();

        ByteArray finalBytes = new()
        {
            Bytes = ByteString.CopyFrom(final)
        };

        await responseStream.WriteAsync(finalBytes);
    }

}

using Google.Protobuf;
using Grpc.Core;
using System;

namespace Cryptography.Client;

class RPC
{
    public static async Task<SHA1HashResult> SHA1HashFileAsync(Cryptography.CryptographyClient client, string filePath)
    {
        using FileStream fileStream = File.OpenRead(filePath);

        long fileSize = new FileInfo(filePath).Length;

        var blockStream = new BlockStream(fileStream, (int)Math.Min(fileSize, 4096));

        var call = client.ComputeSHA1Hash();

        while (await blockStream.MoveNext())
        {
            await call.RequestStream.WriteAsync(new ByteArray { Bytes = blockStream.Current });
        }

        await call.RequestStream.CompleteAsync();

        var response = await call;

        return response;
    }

    public static async Task EncryptBMPFileAsync(Cryptography.CryptographyClient client, string inFilePath, string outPadFilePath, string outFilePath)
    {
        using FileStream inFileStream = File.OpenRead(inFilePath);
        using FileStream outFileStream = File.OpenWrite(outFilePath);
        using FileStream outPadFileStream = File.OpenWrite(outPadFilePath);

        byte[] inBuffer = new byte[54];
        inFileStream.Read(inBuffer);

        using var streamingCall = client.EncryptBMP();

        await streamingCall.RequestStream.WriteAsync(new ByteArray
        {
            Bytes = ByteString.CopyFrom(inBuffer)
        });

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.EncrpytedBytes.Span);
                outPadFileStream.Write(streamingCall.ResponseStream.Current.Pad.Span);
            }
        });

        Array.Resize(ref inBuffer, 4096);

        while (inFileStream.Read(inBuffer) > 0)
        {
            await streamingCall.RequestStream.WriteAsync(new ByteArray
            {
                Bytes = ByteString.CopyFrom(inBuffer)
            });
        }

        await streamingCall.RequestStream.CompleteAsync();
        await response;
    }

    public static async Task DecryptBMPFileAsync(Cryptography.CryptographyClient client, string inFilePath, string inPadFilePath, string outFilePath)
    {
        using FileStream inFileStream = File.OpenRead(inFilePath);
        using FileStream inPadFileStream = File.OpenRead(inPadFilePath);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        /* Read BMP header. */
        byte[] inBuffer = new byte[54];
        inFileStream.Read(inBuffer);

        using var streamingCall = client.DecryptBMP();

        byte[] inPadBuffer = new byte[54];
        inPadFileStream.Read(inPadBuffer);

        await streamingCall.RequestStream.WriteAsync(new OneTimePadResult
        {
            EncrpytedBytes = ByteString.CopyFrom(inBuffer),
            Pad = ByteString.CopyFrom(inPadBuffer)
        }
        );

        Array.Resize(ref inBuffer, 4096);
        Array.Resize(ref inPadBuffer, 4096);

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.Bytes.Span);
            }
        });

        while (inFileStream.Read(inBuffer) > 0 && inPadFileStream.Read(inPadBuffer) > 0)
        {
            await streamingCall.RequestStream.WriteAsync(new OneTimePadResult
            {
                EncrpytedBytes = ByteString.CopyFrom(inBuffer),
                Pad = ByteString.CopyFrom(inPadBuffer)
            });
        }

        await streamingCall.RequestStream.CompleteAsync();
        await response;
    }

    public static async Task EncryptOneTimePadAsync(Cryptography.CryptographyClient client, string inFilePath, string outPadFilePath, string outFilePath)
    {
        using FileStream inFileStream = File.OpenRead(inFilePath);
        using FileStream outFileStream = File.OpenWrite(outFilePath);
        using FileStream outPadFileStream = File.OpenWrite(outPadFilePath);

        byte[] inBuffer = new byte[54];
        inFileStream.Read(inBuffer);

        using var streamingCall = client.EncryptOneTimePad();

        await streamingCall.RequestStream.WriteAsync(new ByteArray
        {
            Bytes = ByteString.CopyFrom(inBuffer)
        });

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.EncrpytedBytes.Span);
                outPadFileStream.Write(streamingCall.ResponseStream.Current.Pad.Span);
            }
        });

        Array.Resize(ref inBuffer, 4096);

        while (inFileStream.Read(inBuffer) > 0)
        {
            await streamingCall.RequestStream.WriteAsync(new ByteArray
            {
                Bytes = ByteString.CopyFrom(inBuffer)
            });
        }

        await streamingCall.RequestStream.CompleteAsync();
        await response;
    }

    public static async Task DecryptOneTimePadAsync(Cryptography.CryptographyClient client, string inFilePath, string inPadFilePath, string outFilePath)
    {
        using var inFileStream = File.OpenRead(inFilePath);
        using var inPadFileStream = File.OpenRead(inPadFilePath);
        using var outFileStream = File.OpenWrite(outFilePath);

        /* Read BMP header. */
        byte[] inBuffer = new byte[54];
        inFileStream.Read(inBuffer);

        using var streamingCall = client.DecryptOneTimePad();

        byte[] inPadBuffer = new byte[54];
        inPadFileStream.Read(inPadBuffer);

        await streamingCall.RequestStream.WriteAsync(new OneTimePadResult
        {
            EncrpytedBytes = ByteString.CopyFrom(inBuffer),
            Pad = ByteString.CopyFrom(inPadBuffer)
        }
        );

        Array.Resize(ref inBuffer, 4096);
        Array.Resize(ref inPadBuffer, 4096);

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.Bytes.Span);
            }
        });

        while (inFileStream.Read(inBuffer) > 0 && inPadFileStream.Read(inPadBuffer) > 0)
        {
            await streamingCall.RequestStream.WriteAsync(new OneTimePadResult
            {
                EncrpytedBytes = ByteString.CopyFrom(inBuffer),
                Pad = ByteString.CopyFrom(inPadBuffer)
            });
        }

        await streamingCall.RequestStream.CompleteAsync();
        await response;
    }

    public static async Task EncryptFourSquareCipherAsync(Cryptography.CryptographyClient client, string inFilePath, string outFilePath, string key1, string key2)
    {
        using StreamReader inFileStream = new(inFilePath);
        using StreamWriter outFileStream = new(outFilePath);

        using var streamingCall = client.EncryptFourSquareCipher();

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.Text);
            }
        });

        await streamingCall.RequestStream.WriteAsync(new FourSquareCipherRequest
        {
            Text = string.Empty,
            Key1 = key1,
            Key2 = key2
        });

        while (inFileStream.Peek() >= 0)
        {
            await streamingCall.RequestStream.WriteAsync(new FourSquareCipherRequest
            {
                Text = inFileStream.ReadLine(),
                Key1 = string.Empty,
                Key2 = string.Empty
            });
        }

        await streamingCall.RequestStream.CompleteAsync();
        await response;
    }

    public static async Task DecryptFourSquareCipherAsync(Cryptography.CryptographyClient client, string inFilePath, string outFilePath, string key1, string key2)
    {
        using StreamReader inFileStream = new(inFilePath);
        using StreamWriter outFileStream = new(outFilePath);

        using var streamingCall = client.DecryptFourSquareCipher();

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.Text);
            }
        });

        await streamingCall.RequestStream.WriteAsync(new FourSquareCipherRequest
        {
            Text = string.Empty,
            Key1 = key1,
            Key2 = key2
        });

        while (inFileStream.Peek() >= 0)
        {
            await streamingCall.RequestStream.WriteAsync(new FourSquareCipherRequest
            {
                Text = inFileStream.ReadLine(),
                Key1 = string.Empty,
                Key2 = string.Empty
            });
        }

        await streamingCall.RequestStream.CompleteAsync();
        await response;
    }

}

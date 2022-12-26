using Cryptography.Ciphers;
using Google.Protobuf;
using Grpc.Core;
using System.Diagnostics;
using System.Text;

namespace Cryptography.Client;

public static class RPC
{
    private const int BufferSize = 1024 * 1024;
    private static readonly int ParallelThreadCount = Environment.ProcessorCount;

    public static async Task<SHA1HashResult> SHA1HashFileAsync(Cryptography.CryptographyClient client, string filePath)
    {
        using BlockFileStreamReader blockStream = new(filePath, BufferSize);

        AsyncClientStreamingCall<ByteArray, SHA1HashResult> call = client.ComputeSHA1Hash();

        while (await blockStream.ReadBlock())
        {
            await call.RequestStream.WriteAsync(new ByteArray { Bytes = blockStream.CurrentBlock });
        }

        await call.RequestStream.CompleteAsync();

        SHA1HashResult response = await call;

        return response;
    }

    public static async Task EncryptBMPFileAsync(Cryptography.CryptographyClient client, string inFilePath, string outPadFilePath, string outFilePath)
    {
        BMPFileHeader bmpHeader = BMPFileHeader.FromFile(inFilePath);

        using BlockFileStreamReader inFileStream = new(inFilePath, BMPFileHeader.BMPHeaderSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);
        using FileStream outPadFileStream = File.OpenWrite(outPadFilePath);

        /* Read BMP bmpHeader. */
        _ = await inFileStream.ReadBlock();

        /* Write unencrypted BMP bmpHeader to file. */
        outFileStream.Write(inFileStream.CurrentBlock.Span);

        inFileStream.BlockSize = BufferSize;

        using AsyncDuplexStreamingCall<ByteArray, OneTimePadResult> streamingCall = client.EncryptOneTimePad();

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.EncrpytedBytes.Span);
                outPadFileStream.Write(streamingCall.ResponseStream.Current.Pad.Span);
            }
        });

        while (await inFileStream.ReadBlock())
        {
            await streamingCall.RequestStream.WriteAsync(new ByteArray
            {
                Bytes = inFileStream.CurrentBlock
            });
        }

        await streamingCall.RequestStream.CompleteAsync();
        await response;
    }

    public static async Task DecryptBMPFileAsync(Cryptography.CryptographyClient client, string inFilePath, string inPadFilePath, string outFilePath)
    {
        BMPFileHeader bmpHeader = BMPFileHeader.FromFile(inFilePath);

        using BlockFileStreamReader inFileStream = new(inFilePath, BMPFileHeader.BMPHeaderSize);
        using BlockFileStreamReader inPadFileStream = new(inPadFilePath, BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        /* Read BMP bmpHeader. */
        _ = await inFileStream.ReadBlock();

        /* Write unencrypted BMP bmpHeader to file. */
        outFileStream.Write(inFileStream.CurrentBlock.Span);

        inFileStream.BlockSize = BufferSize;

        using AsyncDuplexStreamingCall<OneTimePadResult, ByteArray> streamingCall = client.DecryptOneTimePad();

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.Bytes.Span);
            }
        });

        while ((await Task.WhenAll(new[] { inFileStream.ReadBlock(), inPadFileStream.ReadBlock() })).All(x => x))
        {
            await streamingCall.RequestStream.WriteAsync(new OneTimePadResult
            {
                EncrpytedBytes = inFileStream.CurrentBlock,
                Pad = inPadFileStream.CurrentBlock
            });
        }

        await streamingCall.RequestStream.CompleteAsync();
        await response;
    }

    public static async Task EncryptOneTimePadAsync(Cryptography.CryptographyClient client, string inFilePath, string outPadFilePath, string outFilePath)
    {
        using BlockFileStreamReader inFileStream = new(inFilePath, BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);
        using FileStream outPadFileStream = File.OpenWrite(outPadFilePath);

        using AsyncDuplexStreamingCall<ByteArray, OneTimePadResult> streamingCall = client.EncryptOneTimePad();

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.EncrpytedBytes.Span);
                outPadFileStream.Write(streamingCall.ResponseStream.Current.Pad.Span);
            }
        });

        while (await inFileStream.ReadBlock())
        {
            await streamingCall.RequestStream.WriteAsync(new ByteArray
            {
                Bytes = inFileStream.CurrentBlock
            });
        }

        await streamingCall.RequestStream.CompleteAsync();
        await response;
    }

    public static async Task DecryptOneTimePadAsync(Cryptography.CryptographyClient client, string inFilePath, string inPadFilePath, string outFilePath)
    {
        using BlockFileStreamReader inFileStream = new(inFilePath, BufferSize);
        using BlockFileStreamReader inPadFileStream = new(inPadFilePath, BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        using AsyncDuplexStreamingCall<OneTimePadResult, ByteArray> streamingCall = client.DecryptOneTimePad();

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.Bytes.Span);
            }
        });

        while ((await Task.WhenAll(new[] { inFileStream.ReadBlock(), inPadFileStream.ReadBlock() })).All(x => x))
        {
            await streamingCall.RequestStream.WriteAsync(new OneTimePadResult
            {
                EncrpytedBytes = inFileStream.CurrentBlock,
                Pad = inPadFileStream.CurrentBlock
            });
        }

        await streamingCall.RequestStream.CompleteAsync();
        await response;
    }

    private static async Task FourSquareCipherClientFunc(
        Cryptography.CryptographyClient client,
        string inFilePath, string outFilePath, string key1, string key2, bool encrypt)
    {
        using StreamReader inFileStream = new(inFilePath);
        using StreamWriter outFileStream = new(outFilePath);

        using AsyncDuplexStreamingCall<FourSquareCipherRequest, FourSquareCipherResponse> streamingCall =
            encrypt ? client.EncryptFourSquareCipher() : client.DecryptFourSquareCipher();

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.Text);
            }
        });

        
        await streamingCall.RequestStream.WriteAsync(new FourSquareCipherRequest
        {
            Text = inFileStream.ReadLine(),
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

    public static async Task EncryptFourSquareCipherAsync(Cryptography.CryptographyClient client, string inFilePath, string outFilePath, string key1, string key2)
    {
        await FourSquareCipherClientFunc(client, inFilePath, outFilePath, key1, key2, true);
    }

    public static async Task DecryptFourSquareCipherAsync(Cryptography.CryptographyClient client, string inFilePath, string outFilePath, string key1, string key2)
    {
        await FourSquareCipherClientFunc(client, inFilePath, outFilePath, key1, key2, false);
    }

    public static async Task EncryptXXTEAAsync(Cryptography.CryptographyClient client, string inFilePath, string outFilePath, string key, bool parallelize)
    {
        using BlockFileStreamReader inFileStream = new(inFilePath, parallelize ? ParallelThreadCount * BufferSize : BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        if (parallelize)
        {
            using AsyncDuplexStreamingCall<XXTEAParallelRequest, ByteArray> streamingCall = client.EncryptXXTEAParallel();

            var response = Task.Run(async () =>
            {
                while (await streamingCall.ResponseStream.MoveNext())
                {
                    outFileStream.Write(streamingCall.ResponseStream.Current.Bytes.Span);
                }
            });
            await streamingCall.RequestStream.WriteAsync(new XXTEAParallelRequest
            {
                Key = key,
                ThreadCount = ParallelThreadCount
            });

            while (await inFileStream.ReadBlock())
            {
                if (parallelize)
                {
                    await streamingCall.RequestStream.WriteAsync(new XXTEAParallelRequest
                    {
                        Bytes = inFileStream.CurrentBlock
                    });
                }
                else
                {
                    await streamingCall.RequestStream.WriteAsync(new XXTEAParallelRequest
                    {
                        Bytes = inFileStream.CurrentBlock
                    });
                }
            }

            await streamingCall.RequestStream.CompleteAsync();
            await response;
        }
        else
        {
            using AsyncDuplexStreamingCall<XXTEARequest, ByteArray> streamingCall = client.EncryptXXTEA();

            var response = Task.Run(async () =>
            {
                while (await streamingCall.ResponseStream.MoveNext())
                {
                    outFileStream.Write(streamingCall.ResponseStream.Current.Bytes.Span);
                }
            });

            await streamingCall.RequestStream.WriteAsync(new XXTEARequest
            {
                Key = key
            });

            while (await inFileStream.ReadBlock())
            {
                await streamingCall.RequestStream.WriteAsync(new XXTEARequest
                {
                    Bytes = inFileStream.CurrentBlock
                });
            }

            await streamingCall.RequestStream.CompleteAsync();
            await response;
        }
    }

    public static async Task DecryptXXTEAAsync(Cryptography.CryptographyClient client, string inFilePath, string outFilePath, string key, bool parallelize)
    {
        using BlockFileStreamReader inFileStream = new(inFilePath, parallelize ? ParallelThreadCount * BufferSize : BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        if (parallelize)
        {
            using AsyncDuplexStreamingCall<XXTEAParallelRequest, ByteArray> streamingCall = client.DecryptXXTEAParallel();
            var response = Task.Run(async () =>
            {
                while (await streamingCall.ResponseStream.MoveNext())
                {
                    outFileStream.Write(streamingCall.ResponseStream.Current.Bytes.Span);
                }
            });

            await streamingCall.RequestStream.WriteAsync(new XXTEAParallelRequest
            {
                Key = key,
                ThreadCount = ParallelThreadCount
            });

            while (await inFileStream.ReadBlock())
            {
                await streamingCall.RequestStream.WriteAsync(new XXTEAParallelRequest
                {
                    Bytes = inFileStream.CurrentBlock
                });
            }

            await streamingCall.RequestStream.CompleteAsync();
            await response;
        }
        else
        {
            using AsyncDuplexStreamingCall<XXTEARequest, ByteArray> streamingCall = client.DecryptXXTEA();
            var response = Task.Run(async () =>
            {
                while (await streamingCall.ResponseStream.MoveNext())
                {
                    outFileStream.Write(streamingCall.ResponseStream.Current.Bytes.Span);
                }
            });

            await streamingCall.RequestStream.WriteAsync(new XXTEARequest
            {
                Key = key
            });

            while (await inFileStream.ReadBlock())
            {
                await streamingCall.RequestStream.WriteAsync(new XXTEARequest
                {
                    Bytes = inFileStream.CurrentBlock
                });
            }

            await streamingCall.RequestStream.CompleteAsync();
            await response;
        }
    }

    public static async Task EncryptXXTEAOFBAsync(Cryptography.CryptographyClient client, string inFilePath, string outFilePath, string key, string IV)
    {
        byte[] IVbytes = Encoding.ASCII.GetBytes(IV);

        using BlockFileStreamReader inFileStream = new(inFilePath, IVbytes.Length);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        using AsyncDuplexStreamingCall<XXTEAOFBRequest, ByteArray> streamingCall = client.EncryptXXTEAOFB();

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.Bytes.Span);
            }
        });

        await streamingCall.RequestStream.WriteAsync(new XXTEAOFBRequest
        {
            Key = key,
            IV = ByteString.CopyFrom(IVbytes)
        });

        while (await inFileStream.ReadBlock())
        {
            await streamingCall.RequestStream.WriteAsync(new XXTEAOFBRequest
            {
                Bytes = inFileStream.CurrentBlock
            });
        }

        await streamingCall.RequestStream.CompleteAsync();
        await response;
    }

    public static async Task DecryptXXTEAOFBAsync(Cryptography.CryptographyClient client, string inFilePath, string outFilePath, string key, string IV)
    {
        byte[] IVbytes = Encoding.ASCII.GetBytes(IV);

        using BlockFileStreamReader inFileStream = new(inFilePath, IVbytes.Length);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        using AsyncDuplexStreamingCall<XXTEAOFBRequest, ByteArray> streamingCall = client.DecryptXXTEAOFB();

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.Bytes.Span);
            }
        });

        await streamingCall.RequestStream.WriteAsync(new XXTEAOFBRequest
        {
            Key = key,
            IV = ByteString.CopyFrom(IVbytes)
        });

        while (await inFileStream.ReadBlock())
        {
            await streamingCall.RequestStream.WriteAsync(new XXTEAOFBRequest
            {
                Bytes = inFileStream.CurrentBlock
            });
        }

        await streamingCall.RequestStream.CompleteAsync();
        await response;
    }
    public static async Task EncryptDecryptAndCheckSHA1Hash(Cipher cipher, Cryptography.CryptographyClient client, string inFilePath, string key1, string key2)
    {
        try
        {
            string dirPath = new FileInfo(inFilePath).Directory.FullName;

            string fileName = Path.GetFileNameWithoutExtension(inFilePath);
            string fileExt = Path.GetExtension(inFilePath);

            string encryptedFilePath = dirPath + "/" + fileName + ".enc" + fileExt;
            string decryptedFilePath = dirPath + "/" + fileName + ".dec" + fileExt;
            string padFilePath = dirPath + "/" + fileName + ".pad";

            long fileSize = new FileInfo(inFilePath).Length;

            Console.WriteLine($"{BlockFileStreamReader.BytesToString(fileSize)} file");

            var stopwatch = Stopwatch.StartNew();

            switch (cipher)
            {
                case Cipher.BMP:
                    {

                        await EncryptBMPFileAsync(client, inFilePath, padFilePath, encryptedFilePath);
                        Console.WriteLine($"{cipher} encryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        await DecryptBMPFileAsync(client, encryptedFilePath, padFilePath, decryptedFilePath);
                        Console.WriteLine($"{cipher} decryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        break;
                    }
                case Cipher.FourSquareCipher:
                    {
                        await EncryptFourSquareCipherAsync(client, inFilePath, encryptedFilePath, key1, key2);
                        Console.WriteLine($"{cipher} encryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        await DecryptFourSquareCipherAsync(client, encryptedFilePath, decryptedFilePath, key1, key2);
                        Console.WriteLine($"{cipher} decryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        break;
                    }
                case Cipher.OneTimePad:
                    {
                        await EncryptOneTimePadAsync(client, inFilePath, padFilePath, encryptedFilePath);
                        Console.WriteLine($"{cipher} encryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        await DecryptOneTimePadAsync(client, encryptedFilePath, padFilePath, decryptedFilePath);
                        Console.WriteLine($"{cipher} decryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        break;
                    }
                case Cipher.XXTEA:
                    {
                        await EncryptXXTEAAsync(client, inFilePath, encryptedFilePath, key1, false);
                        Console.WriteLine($"{cipher} encryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        await DecryptXXTEAAsync(client, encryptedFilePath, decryptedFilePath, key1, false);
                        Console.WriteLine($"{cipher} decryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        break;
                    }
                case Cipher.XXTEAParallel:
                    {
                        await EncryptXXTEAAsync(client, inFilePath, encryptedFilePath, key1, true);
                        Console.WriteLine($"{cipher} encryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        await DecryptXXTEAAsync(client, encryptedFilePath, decryptedFilePath, key1, true);
                        Console.WriteLine($"{cipher} decryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        break;
                    }
                case Cipher.OFBBlockCipher:
                    {
                        await EncryptXXTEAOFBAsync(client, inFilePath, encryptedFilePath, key1, key2);
                        Console.WriteLine($"{cipher} encryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        await DecryptXXTEAOFBAsync(client, encryptedFilePath, decryptedFilePath, key1, key2);
                        Console.WriteLine($"{cipher} decryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        break;
                    }
            }

            stopwatch.Restart();
            SHA1HashResult sha1Before = await SHA1HashFileAsync(client, inFilePath);
            SHA1HashResult sha1After = await SHA1HashFileAsync(client, decryptedFilePath);

            if (sha1Before.Hash == sha1After.Hash)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"{cipher} cipher SHA1 hashes match [{stopwatch.ElapsedMilliseconds} ms]");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"{cipher} cipher SHA1 hashes do not match [{stopwatch.ElapsedMilliseconds} ms]");
                Console.ResetColor();
            }
        }
        catch (DirectoryNotFoundException e)
        {
            Console.WriteLine(e.Message);
            throw;
        }
    }


}

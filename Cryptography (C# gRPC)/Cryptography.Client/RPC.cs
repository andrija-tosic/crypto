using Cryptography.Bitmap;
using Google.Protobuf;
using Grpc.Core;
using System.Diagnostics;
using System.Text;

namespace Cryptography.Client;

public class RPC
{
    private const int BufferSize = 1024 * 1024;
    private readonly int ParallelThreadCount = Environment.ProcessorCount;
    private readonly Cryptography.CryptographyClient client;

    public RPC(Cryptography.CryptographyClient client)
    {
        this.client = client;
    }

    public async Task<SHA1HashResult> SHA1HashFileAsync(string filePath)
    {
        using BlockFileStreamReader blockStream = new(filePath, BufferSize);

        AsyncClientStreamingCall<ByteArray, SHA1HashResult> call = this.client.ComputeSHA1Hash();

        while (await blockStream.ReadBlock())
        {
            await call.RequestStream.WriteAsync(new ByteArray { Bytes = blockStream.CurrentBlock });
        }

        await call.RequestStream.CompleteAsync();

        SHA1HashResult response = await call;

        return response;
    }

    public async Task EncryptBMPFileAsync(string inFilePath, string outPadFilePath, string outFilePath)
    {
        var bmpHeader = BMPFileHeader.FromFile(inFilePath);

        using BlockFileStreamReader inFileStream = new(inFilePath, BMPFileHeader.BMPHeaderSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);
        using FileStream outPadFileStream = File.OpenWrite(outPadFilePath);

        /* Read BMP header. */
        _ = await inFileStream.ReadBlock();

        /* Write unencrypted BMP header to file. */
        outFileStream.Write(inFileStream.CurrentBlock.Span);

        inFileStream.BlockSize = BufferSize;

        using AsyncDuplexStreamingCall<ByteArray, OneTimePadResult> streamingCall = this.client.EncryptOneTimePad();

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

    public async Task DecryptBMPFileAsync(string inFilePath, string inPadFilePath, string outFilePath)
    {
        var bmpHeader = BMPFileHeader.FromFile(inFilePath);

        using BlockFileStreamReader inFileStream = new(inFilePath, BMPFileHeader.BMPHeaderSize);
        using BlockFileStreamReader inPadFileStream = new(inPadFilePath, BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        /* Read BMP header. */
        _ = await inFileStream.ReadBlock();

        /* Write unencrypted BMP header to file. */
        outFileStream.Write(inFileStream.CurrentBlock.Span);

        inFileStream.BlockSize = BufferSize;

        using AsyncDuplexStreamingCall<OneTimePadResult, ByteArray> streamingCall = this.client.DecryptOneTimePad();

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

    public async Task EncryptOneTimePadAsync(string inFilePath, string outPadFilePath, string outFilePath)
    {
        using BlockFileStreamReader inFileStream = new(inFilePath, BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);
        using FileStream outPadFileStream = File.OpenWrite(outPadFilePath);

        using AsyncDuplexStreamingCall<ByteArray, OneTimePadResult> streamingCall = this.client.EncryptOneTimePad();

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

    public async Task DecryptOneTimePadAsync(string inFilePath, string inPadFilePath, string outFilePath)
    {
        using BlockFileStreamReader inFileStream = new(inFilePath, BufferSize);
        using BlockFileStreamReader inPadFileStream = new(inPadFilePath, BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        using AsyncDuplexStreamingCall<OneTimePadResult, ByteArray> streamingCall = this.client.DecryptOneTimePad();

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

    public async Task EncryptFourSquareCipherAsync(string inFilePath, string outFilePath, string key1, string key2)
    {
        using StreamReader inFileStream = new(inFilePath);
        using StreamWriter outFileStream = new(outFilePath);

        using AsyncDuplexStreamingCall<FourSquareCipherRequest, FourSquareCipherResponse> streamingCall = this.client.EncryptFourSquareCipher();

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

    public async Task DecryptFourSquareCipherAsync(string inFilePath, string outFilePath, string key1, string key2)
    {
        using StreamReader inFileStream = new(inFilePath);
        using StreamWriter outFileStream = new(outFilePath);

        using AsyncDuplexStreamingCall<FourSquareCipherRequest, FourSquareCipherResponse> streamingCall = this.client.DecryptFourSquareCipher();

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

    public async Task EncryptXXTEAAsync(string inFilePath, string outFilePath, string key)
    {
        using BlockFileStreamReader inFileStream = new(inFilePath, BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        long fileSize = new FileInfo(inFilePath).Length;

        using AsyncDuplexStreamingCall<XXTEARequest, ByteArray> streamingCall = this.client.EncryptXXTEA();

        var response = Task.Run(async () =>
        {
            while (await streamingCall.ResponseStream.MoveNext())
            {
                outFileStream.Write(streamingCall.ResponseStream.Current.Bytes.Span);
            }
        });

        await streamingCall.RequestStream.WriteAsync(new XXTEARequest
        {
            Key = key,
            MessageLength = fileSize
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

    public async Task DecryptXXTEAAsync(string inFilePath, string outFilePath, string key)
    {
        using BlockFileStreamReader inFileStream = new(inFilePath, BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        long fileSize = new FileInfo(inFilePath).Length;

        using AsyncDuplexStreamingCall<XXTEARequest, ByteArray> streamingCall = this.client.DecryptXXTEA();
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
                Bytes = inFileStream.CurrentBlock,
                MessageLength = fileSize
            });
        }

        await streamingCall.RequestStream.CompleteAsync();
        await response;
    }

    public async Task EncryptXXTEAParallelAsync(string inFilePath, string outFilePath, string key)
    {
        using BlockFileStreamReader inFileStream = new(inFilePath, this.ParallelThreadCount * BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        long fileSize = new FileInfo(inFilePath).Length;

        using AsyncDuplexStreamingCall<XXTEAParallelRequest, ByteArray> streamingCall = this.client.EncryptXXTEAParallel();

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
            ThreadCount = ParallelThreadCount,
            MessageLength = fileSize
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

    public async Task DecryptXXTEAParallelAsync(string inFilePath, string outFilePath, string key)
    {
        using BlockFileStreamReader inFileStream = new(inFilePath, this.ParallelThreadCount * BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        using AsyncDuplexStreamingCall<XXTEAParallelRequest, ByteArray> streamingCall = this.client.DecryptXXTEAParallel();
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

    public async Task EncryptXXTEAOFBAsync(string inFilePath, string outFilePath, string key, string IV)
    {
        byte[] IVbytes = Encoding.ASCII.GetBytes(IV);

        using BlockFileStreamReader inFileStream = new(inFilePath, BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        long fileSize = new FileInfo(inFilePath).Length;

        using AsyncDuplexStreamingCall<XXTEAOFBRequest, ByteArray> streamingCall = this.client.EncryptXXTEAOFB();

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
            IV = ByteString.CopyFrom(IVbytes),
            MessageLength = fileSize
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

    public async Task DecryptXXTEAOFBAsync(string inFilePath, string outFilePath, string key, string IV)
    {
        byte[] IVbytes = Encoding.ASCII.GetBytes(IV);

        using BlockFileStreamReader inFileStream = new(inFilePath, BufferSize);
        using FileStream outFileStream = File.OpenWrite(outFilePath);

        using AsyncDuplexStreamingCall<XXTEAOFBRequest, ByteArray> streamingCall = this.client.DecryptXXTEAOFB();

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
    public async Task EncryptDecryptAndCheckSHA1Hash(Cipher cipher, string inFilePath, string key1, string key2)
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
                        await this.EncryptBMPFileAsync(inFilePath, padFilePath, encryptedFilePath);
                        Console.WriteLine($"{cipher} encryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        await this.DecryptBMPFileAsync(encryptedFilePath, padFilePath, decryptedFilePath);
                        Console.WriteLine($"{cipher} decryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        break;
                    }
                case Cipher.FourSquareCipher:
                    {
                        await this.EncryptFourSquareCipherAsync(inFilePath, encryptedFilePath, key1, key2);
                        Console.WriteLine($"{cipher} encryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        await this.DecryptFourSquareCipherAsync(encryptedFilePath, decryptedFilePath, key1, key2);
                        Console.WriteLine($"{cipher} decryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        break;
                    }
                case Cipher.OneTimePad:
                    {
                        await this.EncryptOneTimePadAsync(inFilePath, padFilePath, encryptedFilePath);
                        Console.WriteLine($"{cipher} encryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        await this.DecryptOneTimePadAsync(encryptedFilePath, padFilePath, decryptedFilePath);
                        Console.WriteLine($"{cipher} decryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        break;
                    }
                case Cipher.XXTEA:
                    {
                        await this.EncryptXXTEAAsync(inFilePath, encryptedFilePath, key1);
                        Console.WriteLine($"{cipher} encryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        await this.DecryptXXTEAAsync(encryptedFilePath, decryptedFilePath, key1);
                        Console.WriteLine($"{cipher} decryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        break;
                    }
                case Cipher.XXTEAParallel:
                    {
                        await this.EncryptXXTEAParallelAsync(inFilePath, encryptedFilePath, key1);
                        Console.WriteLine($"{cipher} encryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        await this.DecryptXXTEAParallelAsync(encryptedFilePath, decryptedFilePath, key1);
                        Console.WriteLine($"{cipher} decryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        break;
                    }
                case Cipher.OFBBlockCipher:
                    {
                        await this.EncryptXXTEAOFBAsync(inFilePath, encryptedFilePath, key1, key2);
                        Console.WriteLine($"{cipher} encryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        await this.DecryptXXTEAOFBAsync(encryptedFilePath, decryptedFilePath, key1, key2);
                        Console.WriteLine($"{cipher} decryption done [{stopwatch.ElapsedMilliseconds} ms]");

                        break;
                    }
            }

            stopwatch.Restart();
            SHA1HashResult sha1Before = await this.SHA1HashFileAsync(inFilePath);
            SHA1HashResult sha1After = await this.SHA1HashFileAsync(decryptedFilePath);

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

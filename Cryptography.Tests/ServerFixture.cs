extern alias CryptoClient;
extern alias CryptoServer;

using Grpc.Net.Client;
using System.Diagnostics;

namespace Cryptography.Tests;
public class ServerFixture : IDisposable
{
    private readonly Process serverProcess;
    private readonly GrpcChannel channel;

    public CryptoClient::Cryptography.Cryptography.CryptographyClient Client { get; }

    public ServerFixture()
    {
        string projectDir = Resources.Resources.ProjectDirectory;
        string serverDir = Directory.GetParent(projectDir).Parent.FullName + @"\Cryptography.Server\Cryptography.Server.csproj";

        string args = $"run -c Release --project \"{serverDir}\"";

        var processInfo = new ProcessStartInfo("dotnet")
        {
            Arguments = args,
            UseShellExecute = true
        };

        this.serverProcess = Process.Start(processInfo);

        if (this.serverProcess == null)
        {
            Console.WriteLine("Server process failed to start");
        }

        Task.Delay(TimeSpan.FromSeconds(10)).Wait();

        this.channel = GrpcChannel.ForAddress("http://localhost:5150", new GrpcChannelOptions
        {
            MaxReceiveMessageSize = 16 * 1024 * 1024
        });

        this.Client = new CryptoClient::Cryptography.Cryptography.CryptographyClient(this.channel);
    }

    public void Dispose()
    {
        this.channel.Dispose();

        this.serverProcess.Kill();
    }
}

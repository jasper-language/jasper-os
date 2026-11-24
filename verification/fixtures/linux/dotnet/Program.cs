using System.Net.Sockets;

const long expectedChecksum = 150_015_000;
static string Flag(bool value) => value ? "true" : "false";

var checksum = Enumerable.Range(1, 10_000)
    .Select(static value => value * 3L)
    .Sum();

var allocation = new byte[1024 * 1024];
allocation.AsSpan().Fill(0x5a);
GC.Collect();
GC.WaitForPendingFinalizers();
var gcOk = GC.CollectionCount(0) > 0
    && allocation[0] == 0x5a
    && allocation[^1] == 0x5a;
GC.KeepAlive(allocation);

long threadValue = 0;
var worker = new Thread(() => threadValue = checksum);
worker.Start();
worker.Join();
var threadOk = threadValue == expectedChecksum;

var taskValues = await Task.WhenAll(
    Enumerable.Range(0, 4).Select(_ => Task.Run(() => checksum)));
var taskOk = taskValues.All(static value => value == expectedChecksum);

var exceptionOk = false;
try
{
    throw new InvalidOperationException("managed-exception-probe");
}
catch (InvalidOperationException error)
{
    exceptionOk = error.Message == "managed-exception-probe";
}

var probeDirectory = Environment.GetEnvironmentVariable("DOTNET_PROBE_DIR")
    ?? "/data/runtimes/dotnet";
Directory.CreateDirectory(probeDirectory);
var file = Path.Combine(probeDirectory, "probe.tmp");
await File.WriteAllTextAsync(file, "JASPER_DOTNET_FILE_OK");
var fileOk = await File.ReadAllTextAsync(file) == "JASPER_DOTNET_FILE_OK";

var socketPath = Path.Combine(probeDirectory, "probe.sock");
File.Delete(socketPath);
var socketEndpoint = new UnixDomainSocketEndPoint(socketPath);
using var listener = new Socket(
    AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
listener.Bind(socketEndpoint);
listener.Listen(1);
using var client = new Socket(
    AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
await client.ConnectAsync(socketEndpoint);
using var accepted = await listener.AcceptAsync();
var socketPayload = "JASPER_DOTNET_SOCKET_OK"u8.ToArray();
await client.SendAsync(socketPayload);
var socketBytes = new byte[socketPayload.Length];
var socketRead = 0;
while (socketRead < socketBytes.Length)
{
    var count = await accepted.ReceiveAsync(socketBytes.AsMemory(socketRead));
    if (count == 0) break;
    socketRead += count;
}
var socketOk = System.Text.Encoding.ASCII.GetString(socketBytes)
    == "JASPER_DOTNET_SOCKET_OK" && socketRead == socketBytes.Length;
listener.Dispose();
File.Delete(socketPath);

var ok = checksum == expectedChecksum
    && threadOk
    && taskOk
    && gcOk
    && exceptionOk
    && fileOk
    && socketOk;
Console.WriteLine(
    $"DOTNET_PROBE_STATUS checksum={checksum} thread={Flag(threadOk)} " +
    $"task={Flag(taskOk)} gc={Flag(gcOk)} exception={Flag(exceptionOk)} " +
    $"file={Flag(fileOk)} socket={Flag(socketOk)}");
if (!ok)
{
    throw new InvalidOperationException("DOTNET probe invariant failed");
}

Console.WriteLine(
    $"DOTNET_PROBE_OK runtime={Environment.Version} checksum={checksum} " +
    $"thread={Flag(threadOk)} task={Flag(taskOk)} gc={Flag(gcOk)} " +
    $"exception={Flag(exceptionOk)} file={Flag(fileOk)} socket={Flag(socketOk)}");

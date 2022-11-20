using Crypt;

using FileStream fs = new FileStream("D:\\Desktop\\dr dre.jpg", FileMode.Open);
using LazyBinaryReader reader = new LazyBinaryReader(fs, 1024);

int total = 0;

foreach (byte[] buf in reader)
{
    foreach (byte b in buf)
    {
        total++;
        Console.WriteLine(b);
    }
}

Console.WriteLine("Total: " + total);

using System.Diagnostics;

namespace Cryptography.Ciphers;

public class OneTimePad
{
    public static byte[] Encrypt(ref byte[] data)
    {
        byte[] pad = new byte[data.Length];
        Random.Shared.NextBytes(pad);

        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(data[i] ^ pad[i]);
        }

        return pad;
    }
    public static void Decrypt(ref byte[] data, in byte[] pad)
    {
        Debug.Assert(data.Length == pad.Length);

        for (int i = 0; i < pad.Length; i++)
        {
            data[i] = (byte)(data[i] ^ pad[i]);
        }
    }
}

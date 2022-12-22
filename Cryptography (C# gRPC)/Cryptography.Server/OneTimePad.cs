namespace Cryptography.Server;

public class OneTimePad
{
    public byte[] Encrypt(ref byte[] data)
    {
        byte[] pad = new byte[data.Length];
        Random.Shared.NextBytes(pad);

        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(data[i] ^ pad[i]);
        }

        return pad;
    }
    public void Decrypt(ref byte[] data, byte[] pad)
    {
        for (int i = 0; i < pad.Length; i++)
        {
            data[i] = (byte)(data[i] ^ pad[i]);
        }
    }
}

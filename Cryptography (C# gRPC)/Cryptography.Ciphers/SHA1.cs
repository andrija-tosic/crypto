namespace Cryptography.Ciphers;

/*
RFC 3174
https://www.rfc-editor.org/rfc/rfc3174
*/

public class SHA1 : IDisposable
{
    /* Digest. */
    readonly uint[] H = new uint[5]
    {
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0
    };

    ulong l = 0;

    static readonly uint WORDS_PER_BLOCK = 16; // Word = 32-bit.
    static readonly uint BLOCK_BYTES = WORDS_PER_BLOCK * 4;

    /*
        A sequence of constant words K(0), K(1), ... , K(79) is used in the
        SHA-1.  In hex these are given by
    */
    static readonly uint[] K = new uint[80] {
        0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,
        0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,

        0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,
        0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,

        0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,
        0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,

        0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,
        0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6
    };

    /*
		 A sequence of logical functions f(0), f(1),..., f(79) is used in
		 SHA-1.  Each f(t), 0 <= t <= 79, operates on three 32-bit words B, C,
		 D and produces a 32-bit word as output.  f(t;B,C,D) is defined as
		 follows: for words B, C, D,
	*/
    static uint FF(int t, uint B, uint C, uint D)
    {
        if (t >= 0 && t <= 19)
        {
            return (B & C) | ((~B) & D);
        }
        else if (t >= 20 && t <= 39 || t >= 60 && t <= 79)
        {
            return B ^ C ^ D;
        }
        else
        { // if (t >= 40 && t <= 59) {
            return (B & C) | (B & D) | (C & D);
        }
    }

    static uint CircularLeftShift(int n, uint X)
    {
        return (X << n) | (X >> (32 - n));
    }

    static IEnumerable<byte[]> Split(byte[] value, int blockSize)
    {
        int countOfArray = value.Length / blockSize;
        if (value.Length % blockSize > 0)
            countOfArray++;

        for (int i = 0; i < countOfArray; i++)
        {
            yield return value.Skip(i * blockSize).Take(blockSize).ToArray();
        }
    }

    public void ProcessBuffer(byte[] buffer)
    {
        l += (ulong)buffer.Length;
        foreach (byte[] block in Split(buffer, (int)BLOCK_BYTES))
        {
            if (block.Length < BLOCK_BYTES)
            {
                FinalPadMessage(block.ToList());
            }
            else
            {
                HashBlock(block.ToList());
            }
        }
    }

    public string HashHexString
    {
        get
        {
            var result = new System.Text.StringBuilder();
            result.AppendFormat("{0:x8}", H[0]);
            result.AppendFormat("{0:x8}", H[1]);
            result.AppendFormat("{0:x8}", H[2]);
            result.AppendFormat("{0:x8}", H[3]);
            result.AppendFormat("{0:x8}", H[4]);
            return result.ToString();
        }
    }

    void HashBlock(List<byte> block)
    {
        /* a. */
        uint[] W = new uint[80];

        int t;

        for (t = 0; t < 16; t++)
            W[t] = (uint)((block[t * 4] & 0xff) << 24)
            | (uint)((block[t * 4 + 1] & 0xff) << 16)
            | (uint)((block[t * 4 + 2] & 0xff) << 8)
            | (uint)((block[t * 4 + 3] & 0xff) << 0);

        /* b. */
        for (t = 16; t < 80; t++)
            W[t] = CircularLeftShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);

        /* c. */
        uint A = H[0], B = H[1], C = H[2], D = H[3], E = H[4];

        /* d. */
        for (t = 0; t < 80; t++)
        {
            uint TEMP = CircularLeftShift(5, A) + FF(t, B, C, D) + E + W[t] + K[t];

            E = D; D = C; C = CircularLeftShift(30, B); B = A; A = TEMP;
        }

        /* e. */
        H[0] += A;
        H[1] += B;
        H[2] += C;
        H[3] += D;
        H[4] += E;
    }

    void FinalPadMessage(List<byte> message)
    {
        int spaceForLengthAppend = 2 * sizeof(uint);

        // a. "1" is appended.	
        message.Add(0x80);

        /*
            Check to see if the current message block is too small to hold
            the initial padding bits and length.  If so, we will _pad the
            block, process it, and then continue padding into a second
            block.
        */
        if (message.Count > BLOCK_BYTES - spaceForLengthAppend)
        {
            /* Edge case: size of block is between 56 and 64 bytes. One more block transform is needed. */
            /* Both blocks are padded to 64 bytes. */

            while (message.Count < BLOCK_BYTES)
            {
                message.Add(0x00);
            }

            HashBlock(message);

            /* Processing final block. Vector is 64 bytes at this point. */
            message.Capacity = (int)BLOCK_BYTES - spaceForLengthAppend;
            for (int i = 0; i < message.Capacity; i++)
            {
                message[i] = 0x00;
            }
        }
        else
        {
            /*
                b. "0"s are appended.  The number of "0"s will depend on the original
                length of the message.  The last 64 bits of the last 512-bit block
                are reserved for the length l of the original message.
            */
            while (message.Count < BLOCK_BYTES - spaceForLengthAppend)
            {
                message.Add(0x00);
            }
        }

        /*
            c. Obtain the 2-word representation of l, the number of bits in the
            original message.  If l < 2^32 then the first word is all zeroes.
            Append these two words to the padded message.
        */

        l *= 8; /* Convert l from bytes to bits. */

        uint lengthHigh = (uint)(l >> 32);
        uint lengthLow = (uint)l;

        message.Add((byte)(lengthHigh >> 24));
        message.Add((byte)(lengthHigh >> 16));
        message.Add((byte)(lengthHigh >> 8));
        message.Add((byte)lengthHigh);

        message.Add((byte)(lengthLow >> 24));
        message.Add((byte)(lengthLow >> 16));
        message.Add((byte)(lengthLow >> 8));
        message.Add((byte)lengthLow);

        HashBlock(message);
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}

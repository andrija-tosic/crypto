namespace Cryptography.Ciphers;

using System.Linq;
using System.Text;

public class FourSquareCipher
{
    private readonly int gridSize;
    private const char PadCharacter = '*';
    private readonly char[,] grid1;
    private readonly char[,] grid2;

    public FourSquareCipher(string key1, string key2)
    {
        gridSize = (int)Math.Sqrt(key1.Length);
        grid1 = CreateGrid(key1);
        grid2 = CreateGrid(key2);
    }

    private char[,] CreateGrid(string key)
    {
        var grid = new char[gridSize, gridSize];
        var chars = key.ToLower().Distinct().ToArray();
        var i = 0;
        for (int row = 0; row < gridSize; row++)
        {
            for (int col = 0; col < gridSize; col++)
            {
                if (i < chars.Length)
                {
                    grid[row, col] = chars[i];
                    i++;
                }
                else
                {
                    grid[row, col] = PadCharacter;
                }
            }
        }
        return grid;
    }

    private (int row, int col) FindCharInGrid(char[,] grid, char c)
    {
        for (int row = 0; row < gridSize; row++)
        {
            for (int col = 0; col < gridSize; col++)
            {
                if (grid[row, col] == c)
                {
                    return (row, col);
                }
            }
        }
        return (-1, -1);
    }

    public string EncryptText(string plaintext)
    {
        var ciphertext = new StringBuilder();

        var sb = new StringBuilder(plaintext.Length);
        foreach (var c in plaintext.Where(char.IsLetter))
        {
            sb.Append(char.ToLower(c));
        }

        plaintext = sb.ToString();

        for (int i = 0; i < plaintext.Length; i += 2)
        {
            var c1 = plaintext[i];
            var c2 = (i + 1 < plaintext.Length) ? plaintext[i + 1] : PadCharacter;
            var (row1, col1) = FindCharInGrid(grid1, c1);
            var (row2, col2) = FindCharInGrid(grid2, c2);

            if (row1 != -1 && col2 != -1)
            {
                ciphertext.Append(grid2[row1, col2]);
            }
            else
            {
                plaintext.Append(PadCharacter);
            }

            if (row2 != -1 && col1 != -1)
            {
                ciphertext.Append(grid1[row2, col1]);
            }
            else
            {
                plaintext.Append(PadCharacter);
            }
        }
        return ciphertext.ToString();
    }

    public string DecryptText(string ciphertext)
    {
        var plaintext = new StringBuilder(ciphertext.Length);
        for (int i = 0; i < ciphertext.Length; i += 2)
        {
            var c1 = ciphertext[i];
            var c2 = ciphertext[i + 1];
            var (row1, col1) = FindCharInGrid(grid2, c1);
            var (row2, col2) = FindCharInGrid(grid1, c2);
            if (row1 != -1 && col2 != -1)
            {
                plaintext.Append(grid1[row1, col2]);
            }
            if (row2 != -1 && col1 != -1)
            {
                plaintext.Append(grid2[row2, col1]);
            }
        }
        return plaintext.ToString();
    }
}

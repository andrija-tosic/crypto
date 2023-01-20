using System.Text;

namespace Cryptography.Ciphers;
public class FourSquareCipher
{
    private readonly int gridSize;
    private const char PadCharacter = 'x';
    private const string PadCharacterAsString = "x";
    private readonly char[,] grid1;
    private readonly char[,] grid2;

    public FourSquareCipher(string key1, string key2)
    {
        this.gridSize = (int)Math.Sqrt(key1.Length);
        this.grid1 = this.CreateGrid(key1);
        this.grid2 = this.CreateGrid(key2);
    }

    private char[,] CreateGrid(string key)
    {
        char[,] grid = new char[this.gridSize, this.gridSize];
        char[] chars = key.ToLower().Distinct().ToArray();
        int i = 0;
        for (int row = 0; row < this.gridSize; row++)
        {
            for (int col = 0; col < this.gridSize; col++)
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
        for (int row = 0; row < this.gridSize; row++)
        {
            for (int col = 0; col < this.gridSize; col++)
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
        foreach (char c in plaintext.Where(char.IsLetter))
        {
            _ = sb.Append(char.ToLower(c));
        }

        plaintext = sb.ToString();

        for (int i = 0; i < plaintext.Length; i += 2)
        {
            char c1 = plaintext[i];
            char c2 = (i + 1 < plaintext.Length) ? plaintext[i + 1] : PadCharacter;
            (int row1, int col1) = this.FindCharInGrid(this.grid1, c1);
            (int row2, int col2) = this.FindCharInGrid(this.grid2, c2);

            if (row1 != -1 && col2 != -1)
            {
                _ = ciphertext.Append(this.grid2[row1, col2]);
            }
            else
            {
                _ = ciphertext.Append(PadCharacter);
            }

            if (row2 != -1 && col1 != -1)
            {
                _ = ciphertext.Append(this.grid1[row2, col1]);
            }
            else
            {
                _ = ciphertext.Append(PadCharacter);
            }
        }

        return ciphertext.ToString();
    }

    public string DecryptText(string ciphertext)
    {
        var plaintext = new StringBuilder(ciphertext.Length);
        for (int i = 0; i < ciphertext.Length; i += 2)
        {
            char c1 = ciphertext[i];
            char c2 = ciphertext[i + 1];
            (int row1, int col1) = this.FindCharInGrid(this.grid2, c1);
            (int row2, int col2) = this.FindCharInGrid(this.grid1, c2);
            if (row1 != -1 && col2 != -1)
            {
                _ = plaintext.Append(this.grid1[row1, col2]);
            }

            if (row2 != -1 && col1 != -1)
            {
                _ = plaintext.Append(this.grid2[row2, col1]);
            }
        }

        return plaintext.Replace(PadCharacterAsString, "").ToString();
    }
}

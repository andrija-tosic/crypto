namespace Cryptography.Server;

using System.Collections.Generic;
using System.Linq;

public class Pair<T1, T2>
{
    public T1 First { get; set; }
    public T2 Second { get; set; }
}
public class FourSquareCipher
{
    static List<Pair<char, char>> TextToBigrams(string text)
    {
        var bigrams = new List<Pair<char, char>>();

        text = new string(text.Where(c => !char.IsWhiteSpace(c)).ToArray());

        for (int i = 0; i < text.Length; i += 2)
        {
            var chars = new Pair<char, char> { First = ' ', Second = ' ' };

            chars.First = text[i];

            if (i + 1 < text.Length)
            {
                chars.Second = text[i + 1];
            }
            else
            {
                chars.Second = ' ';
            }

            bigrams.Add(chars);
        }

        return bigrams;
    }

    static string BigramsToText(List<Pair<char, char>> bigrams)
    {
        return string.Join("", bigrams.Select(b => new string(new char[] { b.First, b.Second })));
    }

    public static string EncryptText(string text, string keyBlock1, string keyBlock2)
    {
        List<Pair<char, char>> bigrams = TextToBigrams(text);
        const string alphabetBlock = "abcdefghijklmnoprstuvwxyz";

        for (int i = 0; i < bigrams.Count; i++)
        {
            char fst = bigrams[i].First;
            char snd = bigrams[i].Second;

            int loc1 = alphabetBlock.IndexOf(fst);
            int loc2 = alphabetBlock.IndexOf(snd);

            if (loc1 != -1)
            {
                bigrams[i].First = keyBlock1[5 * (loc1 / 5) + loc2 % 5];
            }

            if (loc2 != -1)
            {
                bigrams[i].Second = keyBlock2[loc1 % 5 + 5 * (loc2 / 5)];
            }
        }
        return BigramsToText(bigrams);
    }

    public static string DecryptText(string text, string keyBlock1, string keyBlock2)
    {
        List<Pair<char, char>> bigrams = TextToBigrams(text);
        const string alphabet_block = "abcdefghiklmnopqrstuvwxyz";

        for (int i = 0; i < bigrams.Count; i++)
        {
            char fst = bigrams[i].First;
            char snd = bigrams[i].Second;

            int loc1 = keyBlock1.IndexOf(fst);
            int loc2 = keyBlock2.IndexOf(snd);

            if (loc1 != -1)
            {
                bigrams[i].First = alphabet_block[5 * (loc1 / 5) + loc2 % 5];
            }

            if (loc2 != -1)
            {
                bigrams[i].Second = alphabet_block[loc1 % 5 + 5 * (loc2 / 5)];
            }
        }
        return BigramsToText(bigrams);
    }
}

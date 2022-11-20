using System.Collections;

namespace Crypt;

public class LazyBinaryReader : BinaryReader, IEnumerable<byte[]>
{
    private readonly int _bufferSize;
        public LazyBinaryReader(Stream input, int bufferSize)
            : base(input)
        {
            this._bufferSize = bufferSize;
        }

        public LazyBinaryReader(Stream input, System.Text.Encoding encoding, int bufferSize)
            : base(input, encoding)
        {
            this._bufferSize = bufferSize;
        }

        public IEnumerator<byte[]> GetEnumerator()
        {
            while (BaseStream.Position < BaseStream.Length)
                yield return ReadBytes(_bufferSize);
        }
        
        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using PassiveAgression.Core.Static;
using static PassiveAgression.Core.Win32.Natives;

namespace PassiveAgression.Core
{
    internal class Misc
    {
        /// <summary>
        /// Converts hex stream to byte array. 
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public static byte[] HexStringToBytes(string hex)
        {
            hex = hex.Replace(" ", ""); // Remove spaces if any
            byte[] bytes = new byte[hex.Length / 2];

            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }

        /// <summary>
        /// Concats 2 byte arrays
        /// </summary>
        /// <param name="arrays"></param>
        /// <returns></returns>
        public static byte[] ConcatByteArrays(params byte[][] arrays)
        {
            byte[] rv     = new byte[arrays.Sum(a => a.Length)];
            int    offset = 0;
            foreach (byte[] array in arrays)
            {
                System.Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }

        /// <summary>
        /// returns a string with ascii characters in the given byte array
        /// </summary>
        /// <param name="byteArray"></param>
        /// <param name="startIndex"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static string GetAsciiCharacters(byte[] byteArray, int startIndex, int count)
        {
            StringBuilder asciiChars = new StringBuilder();

            for (int i = startIndex; i < startIndex + count; i++)
            {
                if (i < byteArray.Length)
                {
                    if (byteArray[i] >= 32 && byteArray[i] <= 126)
                    {
                        asciiChars.Append((char)byteArray[i]);
                    }
                    else
                    {
                        asciiChars.Append('.');
                    }
                }
                else
                {
                    asciiChars.Append(' '); // Add padding for last line if needed
                }
            }

            return asciiChars.ToString();
        }

        /// <summary>
        /// Thanks: https://www.codeproject.com/Articles/36747/Quick-and-Dirty-HexDump-of-a-Byte-Array
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="bytesPerLine"></param>
        public static void DisplayHexDump(byte[] bytes, int bytesPerLine = 16)
        {
            if (bytes == null) return;
            int bytesLength = bytes.Length;

            char[] HexChars = "0123456789ABCDEF".ToCharArray();

            int firstHexColumn =
                  8                   // 8 characters for the address
                + 3;                  // 3 spaces

            int firstCharColumn = firstHexColumn
                + bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
                + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
                + 2;                  // 2 spaces 

            int lineLength = firstCharColumn
                + bytesPerLine           // - characters to show the ascii value
                + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

            char[] line = (new String(' ', lineLength - Environment.NewLine.Length) + Environment.NewLine).ToCharArray();
            int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
            StringBuilder result = new StringBuilder(expectedLines * lineLength);

            for (int i = 0; i < bytesLength; i += bytesPerLine)
            {
                line[0] = HexChars[(i >> 28) & 0xF];
                line[1] = HexChars[(i >> 24) & 0xF];
                line[2] = HexChars[(i >> 20) & 0xF];
                line[3] = HexChars[(i >> 16) & 0xF];
                line[4] = HexChars[(i >> 12) & 0xF];
                line[5] = HexChars[(i >> 8) & 0xF];
                line[6] = HexChars[(i >> 4) & 0xF];
                line[7] = HexChars[(i >> 0) & 0xF];

                int hexColumn = firstHexColumn;
                int charColumn = firstCharColumn;

                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= bytesLength)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        byte b = bytes[i + j];
                        line[hexColumn] = HexChars[(b >> 4) & 0xF];
                        line[hexColumn + 1] = HexChars[b & 0xF];
                        //line[charColumn] = (b < 32 ? '·' : (char)b);
                        line[charColumn] = (b >= 32 && b <= 126 ? (char)b : '·');
                    }
                    hexColumn += 3;
                    charColumn++;
                }
                result.Append(line);
            }
            Console.WriteLine(result.ToString());
        }

        /// <summary>
        /// Finds index of sequence of bytes in array
        /// </summary>
        /// <param name="byteArray"></param>
        /// <param name="sequenceToFind"></param>
        /// <returns></returns>
        public static int FindSequence(byte[] byteArray, byte[] sequenceToFind)
        {
            for (int i = 0; i <= byteArray.Length - sequenceToFind.Length; i++)
            {
                bool found = true;

                for (int j = 0; j < sequenceToFind.Length; j++)
                {
                    if (byteArray[i + j] != sequenceToFind[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    return i;
                }
            }

            return -1; // Sequence not found
        }

        /// <summary>
        /// Checks if all items in an array have the same value
        /// </summary>
        /// <param name="byteArray"></param>
        /// <returns></returns>
        public static bool AllItemsAreSame(byte[] byteArray)
        {
            if (byteArray.Length == 0)
            {
                return true; // Empty array is considered to have the same items
            }

            byte firstValue = byteArray[0];

            for (int i = 1; i < byteArray.Length; i++)
            {
                if (byteArray[i] != firstValue)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Calculates CRC32 based on input
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static uint CalcCrc32(byte[] data)
        {
            uint dwCRC = 0xFFFFFFFF;
            for (int i = 0; i < data.Length; i++)
            {
                dwCRC = (dwCRC >> 8) ^ Static.Win32.dwCrc32Table[(data[i]) ^ (dwCRC & 0x000000FF)];
            }
            dwCRC = ~dwCRC;
            return dwCRC;
        }

        /// <summary>
        /// Converts a byte array with signed bytes to an array with unsigned bytes
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] ConvertSignedByteArrayToUnsigned(sbyte[] data)
        {
            byte[] unsignedByteArray = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                unsignedByteArray[i] = (byte)data[i];
            }

            return unsignedByteArray;
        }

        /// <summary>
        /// Returns a human readable form of samaccounttype
        /// </summary>
        /// <param name="accountType"></param>
        /// <returns></returns>
        public static string SamAccountTypeToString(uint accountType)
        {
            SamAccountType sat = (SamAccountType)accountType;
            return sat.ToString();
        }

        /// <summary>
        /// Encodes given bytes into a struct of type T
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="array"></param>
        /// <returns></returns>
        public static T ReadStruct<T>(byte[] array)
            where T : struct
        {

            GCHandle handle   = GCHandle.Alloc(array, GCHandleType.Pinned);
            var      mystruct = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return mystruct;
        }

        /// <summary>
        /// Reads memory from given Ptr and returns encoded struct of type T
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="addr"></param>
        /// <returns></returns>
        public static T ReadStruct<T>(IntPtr addr)
            where T : struct
        {
            T str = (T)Marshal.PtrToStructure(addr, typeof(T));

            return str;
        }

        /// <summary>
        /// Returns human readable string of given bytearray
        /// </summary>
        /// <param name="byteArray"></param>
        /// <returns></returns>
        public static string PrintHashBytes(byte[] byteArray)
        {
            if (byteArray == null)
                return string.Empty;

            StringBuilder res = new StringBuilder(byteArray.Length * 2);
            for (int i = 0; i < byteArray.Length; i++)
            {
                res.AppendFormat(NumberFormatInfo.InvariantInfo, "{0:x2}", byteArray[i]);
            }
            return res.ToString();
        }

        public static byte[] MergeBlocks(byte[] block1, byte[] block2)
        {
            byte[] outBlock = new byte[block1.Length + block2.Length];
            Array.Copy(block1, outBlock, block1.Length);
            Array.Copy(block2, 0, outBlock, block1.Length, block2.Length);

            return outBlock;
        }

        /// <summary>
        /// Removes colons and dashes from hexstring
        /// </summary>
        /// <param name="hashData"></param>
        /// <returns></returns>
        public static string CleanHexData(string hashData)
        {
            if (!string.IsNullOrEmpty(hashData))
                return hashData.Replace(":", "").Replace("-", "");

            return hashData;
        }

        /// <summary>
        /// Converts the given ATTId from Big Engian to Little Endian
        /// This can be used to lookup the existence of an ATTId in a stream that is LE
        /// </summary>
        /// <param name="att"></param>
        /// <returns></returns>
        public static string GetAttIdInLEHexString(Enums.ATTIds att)
        {
            string hexUnicodePwd = att.ToString("X");

            byte[] bytes = Enumerable.Range(0, hexUnicodePwd.Length)
                                     .Where(x => x % 2 == 0)
                                     .Select(x => Convert.ToByte(hexUnicodePwd.Substring(x, 2), 16))
                                     .ToArray();

            Array.Reverse(bytes);

            // Convert the byte array back to a hex string
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        /// <summary>
        /// Reads wchars from a byte array and returns the unicode string
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string ReadWChars(ref byte[] data)
        {
            int length = 0;

            // Determine the length of the null-terminated string.
            while (data[length] != 0 || data[length + 1] != 0)
            {
                length += 2; // Assuming a null-terminated wide character string.
            }

            // we do know the length of the handle now
            string w_string = System.Text.Encoding.Unicode.GetString(data, 0, length);

            return w_string;
        }

        public static int FieldOffset<T>(string fieldName)
        {
            return Marshal.OffsetOf(typeof(T), fieldName).ToInt32();
        }


    }
}

using System;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace DimSys.Cryptography {

    public class Cryptography : IDisposable {
        /// <summary>
        /// Salt byte array to make it harder to guess our key using a dictionary attack 
        /// </summary>
        private readonly byte[] m_salt = new byte[] { 0x99, 0x76, 0x61, 0xe6, 0x20, 0x4d, 0x65, 0x46, 0x76, 0x33, 0x64, 0x81, 0x76 };

        /// <summary>
        /// Private internal key.
        /// </summary>
        private readonly string m_InternalKey = "skj%$#&YTRfdst5675UJye6487srtghbf8ujh563#$%&/ikjhgsdj631";

        private Aes m_Aes = null;
        private readonly int m_AlgorithmMaxKeySize;
        private readonly int m_AlgorithmMaxIVSize;

        public Cryptography()
        {
            m_Aes = Aes.Create();

            m_AlgorithmMaxKeySize = m_Aes.LegalKeySizes.Select(s => s.MaxSize).ToArray().Max();
            m_AlgorithmMaxIVSize = m_Aes.LegalBlockSizes.Select(s => s.MaxSize).ToArray().Max();

            //mode of operation. there are other 4 modes. 
            m_Aes.Mode = CipherMode.CBC;
            //padding mode(if any extra byte added)
            m_Aes.Padding = PaddingMode.PKCS7;

        }

        #region Derive data for key
        /// <summary>
        /// Derives the data returning a 64 Byte / 512 bits Array.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Derive64(string data)
        {
            return _derive(data, 64);
        }

        /// <summary>
        /// Derives the data returning a 32 Byte / 256 bits Array.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Derive32(string data)
        {
            return _derive(data, 32);
        }

        /// <summary>
        /// Derives the data returning a 24 Byte / 192 bits Array.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Derive24(string data)
        {
            return _derive(data, 24);
        }

        /// <summary>
        /// Derives the data returning a 16 Byte / 128 bits Array.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Derive16(string data)
        {
            return _derive(data, 16);
        }

        /// <summary>
        /// Derives the data returning a 8 Byte / 64 bits Array.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] Derive8(string data) {
            return _derive(data, 8);
        }

        /// <summary>
        /// Derives the data in request byte size.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="b">Byte size</param>
        /// <returns></returns>
        private byte[] _derive(string data, int b) {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(data, m_salt);
            return pdb.GetBytes(b);
        }
        #endregion

        private void SetKeyAndIV() {
            switch (m_AlgorithmMaxKeySize)
            {
                case 64:
                    m_Aes.Key = Derive8(m_InternalKey);
                    break;
                case 128:
                    m_Aes.Key = Derive16(m_InternalKey);
                    break;
                case 192:
                    m_Aes.Key = Derive24(m_InternalKey);
                    break;
                case 256:
                    m_Aes.Key = Derive32(m_InternalKey);
                    break;
                default:
                    m_Aes.Key = Derive24(m_InternalKey);
                    break;
            }
            //Derive IV accordingly
            switch (m_Aes.BlockSize / 8)
            {
                case 8:
                    m_Aes.IV = Derive8(m_InternalKey);
                    break;
                case 16:
                    m_Aes.IV = Derive16(m_InternalKey);
                    break;
                case 24:
                    m_Aes.IV = Derive24(m_InternalKey);
                    break;
                case 32:
                    m_Aes.IV = Derive32(m_InternalKey);
                    break;
                default:
                    m_Aes.IV = Derive8(m_InternalKey);
                    break;
            }

        }

        /// <summary>
        /// Gets the byte array from a string.
        /// <para>The encoding is UTF8.</para>
        /// </summary>
        /// <param name="value">Value to convert.</param>
        /// <returns>The byte array using <see cref="UTF8Encoding"/></returns>
        private byte[] GetBytesFromString(string value) {
            return UTF8Encoding.UTF8.GetBytes(value);
        }

        /// <summary>
        /// Gets the string from a byte array.
        /// <para>The encoding is UTF8.</para>
        /// </summary>
        /// <param name="value">Value to convert.</param>
        /// <returns>The string representation using <see cref="UTF8Encoding"/></returns>
        private string GetStringFromBytes(byte[] value) {
            return UTF8Encoding.UTF8.GetString(value);
        }

        /// <summary>
        /// This methods replace unsafe characters after encoding.
        /// </summary>
        /// <param name="arg"></param>
        /// <returns></returns>
        private string Base64UrlEncode(byte[] arg) {
            string s = Convert.ToBase64String(arg); // Regular base64 encoder
            s = s.Split('=')[0]; // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding
            return s;
        }

        /// <summary>
        /// This methods replace unsafe characters before decoding.
        /// </summary>
        /// <param name="arg"></param>
        /// <returns></returns>
        private byte[] Base64UrlDecode(string arg) {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default: throw new Exception("Illegal base64url string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        }

        public string Encrypt(string value) {
            if (string.IsNullOrEmpty(value))
                throw new ArgumentNullException("value");

            SetKeyAndIV();

            byte[] resultArray;
            //get the byte code of the string
            byte[] EncryptArray = null;

            ICryptoTransform cTransform = m_Aes.CreateEncryptor();
            EncryptArray = GetBytesFromString(value);

            resultArray = cTransform.TransformFinalBlock(EncryptArray, 0, EncryptArray.Length);
            //Release resources held by TripleDes Encryptor                
            //m_Aes.Clear();

            if (resultArray == null || resultArray.Length == 0)
                return null;

            return Base64UrlEncode(resultArray);
        }

        public string Decrypt(string value) {
            if (string.IsNullOrEmpty(value))
                throw new ArgumentNullException("value");

            SetKeyAndIV();

            byte[] resultArray;
            //get the byte code of the string
            byte[] EncryptArray = null;

            ICryptoTransform cTransform = m_Aes.CreateDecryptor();
            EncryptArray = Base64UrlDecode(value);

            resultArray = cTransform.TransformFinalBlock(EncryptArray, 0, EncryptArray.Length);
            //Release resources held by TripleDes Encryptor                
            //m_Aes.Clear();

            if (resultArray == null || resultArray.Length == 0)
                return null;

            //return the Clear decrypted TEXT
            return GetStringFromBytes(resultArray);

        }

        public void Dispose() {
            if (m_Aes != null)
                m_Aes.Dispose();
        }
    }
}

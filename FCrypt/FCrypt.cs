using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using System.Xml.XPath;

namespace FCrypt {

    /// <summary>
    /// AES type
    /// </summary>
    public enum CipherType {
        /// <summary>
        /// AES 128bit
        /// </summary>
        AES128 = 16,
        /// <summary>
        /// AES 256bit
        /// </summary>
        AES256 = 32
    }

    /// <summary>
    /// Encrypts and Decrypts file.
    /// </summary>
    public class FCrypt {

        /// <summary>
        /// Initial vector
        /// </summary>
        private static readonly byte[] aesIV;
        /// <summary>
        /// Salt value
        /// </summary>
        private static readonly byte[] keySalt;

        /// <summary>
        /// Initializes
        /// </summary>
        static FCrypt() {
            var encoder = new UTF8Encoding();
            var assembly = Assembly.GetExecutingAssembly();
            using( Stream stream = assembly.GetManifestResourceStream( "FCrypt.option.xml" ) ) {
                var xml = XDocument.Load( stream );
                aesIV = encoder.GetBytes( xml.XPathSelectElement( "/cipher/iv" ).Value );
                keySalt = encoder.GetBytes( xml.XPathSelectElement( "/cipher/salt" ).Value );
            }
        }

        /// <summary>
        /// Generates a key
        /// </summary>
        /// <param name="password">Password</param>
        /// <param name="cipherType">Cipher type (AES 128bit or AES 256bit)</param>
        /// <returns>Key for AES</returns>
        private static byte[] GenerateKey( string password, CipherType cipherType ) => new Rfc2898DeriveBytes( password, keySalt, 1000 ).GetBytes( ( int )cipherType );

        /// <summary>
        /// Encrypts a file
        /// </summary>
        /// <param name="inputFilePath">Original file path</param>
        /// <param name="outputFilePath">Encrypted file path</param>
        /// <param name="password">Password</param>
        /// <param name="cipherType">Cipher type (AES 128bit or AES 256bit)</param>
        public static void Encrypt( string inputFilePath, string outputFilePath, string password, CipherType cipherType = CipherType.AES128 ) {
            var key = GenerateKey( password, cipherType );

            var cipher = new AesManaged {
                KeySize = ( int )cipherType * 8,
                Key = key,
                BlockSize = 128,
                Mode = CipherMode.CBC,
                IV = aesIV,
                Padding = PaddingMode.PKCS7
            };

            using( var ifs = new FileStream( inputFilePath, FileMode.Open, FileAccess.Read ) ) {
                var ibuf = new byte[ifs.Length];
                ifs.Read( ibuf, 0, ibuf.Length );

                var obuf = cipher.CreateEncryptor().TransformFinalBlock( ibuf, 0, ibuf.Length );

                using( var ofs = new FileStream( outputFilePath, FileMode.Create, FileAccess.Write ) ) {
                    var headBuf = BitConverter.GetBytes( ( int )cipherType );
                    ofs.Write( headBuf, 0, headBuf.Length );
                    ofs.Write( obuf, 0, obuf.Length );
                }
            }
        }

        /// <summary>
        /// Decrypts a file
        /// </summary>
        /// <param name="inputFilePath">Encrypted file path</param>
        /// <param name="outputFilePath">Decrypted file path</param>
        /// <param name="password">Password</param>
        public static void Decrypt( string inputFilePath, string outputFilePath, string password ) {

            using( var ifs = new FileStream( inputFilePath, FileMode.Open, FileAccess.Read ) ) {
                var headBuf = new byte[sizeof( int )];
                var ibuf = new byte[ifs.Length - headBuf.Length];
                ifs.Read( headBuf, 0, headBuf.Length );
                ifs.Read( ibuf, 0, ibuf.Length );

                var cipherType = ( CipherType )BitConverter.ToInt32( headBuf );

                var key = GenerateKey( password, cipherType );

                var cipher = new AesManaged {
                    KeySize = ( int )cipherType * 8,
                    Key = key,
                    BlockSize = 128,
                    Mode = CipherMode.CBC,
                    IV = aesIV,
                    Padding = PaddingMode.PKCS7
                };

                var obuf = cipher.CreateDecryptor().TransformFinalBlock( ibuf, 0, ibuf.Length );

                using( var ofs = new FileStream( outputFilePath, FileMode.Create, FileAccess.Write ) ) {
                    ofs.Write( obuf, 0, obuf.Length );
                }
            }
        }
    }
}

using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace FCrypt {

    /// <summary>
    /// Encrypts and Decrypts file.
    /// </summary>
    public class FCrypt {

        /// <summary>
        /// Salt value
        /// </summary>
        private static readonly byte[] keySalt;
        /// <summary>
        /// Key size (bit)
        /// </summary>
        const int KeySize = 256;
        /// <summary>
        /// Block size (bit)
        /// </summary>
        const int BlockSize = 128;
        /// <summary>
        /// Buffer size (256KiB)
        /// </summary>
        const int BufferSize = 1024 * 256;


        /// <summary>
        /// Initializes
        /// </summary>
        static FCrypt() {
            var encoder = new UTF8Encoding();
            keySalt = encoder.GetBytes( "8HRd1vfMHOAKgIg5lS6A+uma6C10cjPhd0pDAN8WJYA=" );
        }

        /// <summary>
        /// Generates a key
        /// </summary>
        /// <param name="password">Password</param>
        /// <returns>Key for AES</returns>
        private static byte[] GenerateKey( string password ) => new Rfc2898DeriveBytes( password, keySalt, 1000 ).GetBytes( KeySize / 8 );

        /// <summary>
        /// Encrypts a file
        /// </summary>
        /// <param name="inputFilePath">Original file path</param>
        /// <param name="outputFilePath">Encrypted file path</param>
        /// <param name="password">Password</param>
        public static void Encrypt( string inputFilePath, string outputFilePath, string password ) {
            var key = GenerateKey( password );

            var cipher = new AesManaged {
                KeySize = KeySize,
                Key = key,
                BlockSize = BlockSize,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };
            cipher.GenerateIV();

            /**
             * 1. Reads the ogrinal data. (FileStream)
             * 2. Writes a initial vector. (FileStream)
             * 3. Compresses the encrypted data. (DeflateStream)
             * 4. Encrypts the data. (CryptoStream)
             * 5. Writes the compressed data. (FileStream)
             */
            using( var ifs = new FileStream( inputFilePath, FileMode.Open, FileAccess.Read ) ) {
                using( var ofs = new FileStream( outputFilePath, FileMode.Create, FileAccess.Write ) ) {
                    ofs.Write( cipher.IV, 0, cipher.IV.Length );
                    using( var encryptor = cipher.CreateEncryptor() ) {
                        using( var ocfs = new CryptoStream( ofs, encryptor, CryptoStreamMode.Write ) ) {
                            using( var odcfs = new DeflateStream( ocfs, CompressionMode.Compress, true ) ) {
                                var buf = new byte[BufferSize];
                                for( int size = ifs.Read( buf, 0, buf.Length ); size > 0; size = ifs.Read( buf, 0, buf.Length ) ) {
                                    odcfs.Write( buf, 0, size );
                                }
                            }
                        }
                    }
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
                var headBuf = new byte[BlockSize / 8];
                ifs.Read( headBuf, 0, headBuf.Length );
                var key = GenerateKey( password );

                var cipher = new AesManaged {
                    KeySize = KeySize,
                    Key = key,
                    BlockSize = BlockSize,
                    Mode = CipherMode.CBC,
                    IV = headBuf,
                    Padding = PaddingMode.PKCS7
                };

                using( var decryptor = cipher.CreateDecryptor() ) {
                    using( var icfs = new CryptoStream( ifs, decryptor, CryptoStreamMode.Read ) ) {
                        using( var idcfs = new DeflateStream( icfs, CompressionMode.Decompress, true ) ) {
                            using( var ofs = new FileStream( outputFilePath, FileMode.Create, FileAccess.Write ) ) {
                                var buf = new byte[BufferSize];
                                for( int size = idcfs.Read( buf, 0, buf.Length ); size > 0; size = idcfs.Read( buf, 0, buf.Length ) ) {
                                    ofs.Write( buf, 0, size );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

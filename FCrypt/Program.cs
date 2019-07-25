using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace FCrypt {
    class Program {

        /// <summary>
        /// Encrypt or Decrypt
        /// </summary>
        enum EncryptOrDecrypt {
            Unknown,
            Encrypt,
            Decrypt
        }

        static int Main( string[] args ) {

            var (encDec, inputFilePath, outputFilePath, password) = ParseCommand( args );
            if( encDec == EncryptOrDecrypt.Unknown || string.IsNullOrEmpty( inputFilePath ) ) {
                Console.WriteLine( "Usage: FCrypt -e|-d -i InputFilePath [-o OutputFilePath] [-p Password]" );
                Console.WriteLine();
                Console.WriteLine( "  -e\t\t\tEncrypt" );
                Console.WriteLine( "  -d\t\t\tDecrypt" );
                Console.WriteLine( "  <Encrypt>" );
                Console.WriteLine( "    -i InputFilePath\tOriginal file path" );
                Console.WriteLine( "    -o OutputFilePath\tEncrypted file path (If empty, {InputFilePath}.fcrypt)" );
                Console.WriteLine( "    -p Password\t\tPassword (If empty, it will be prompted for input.)" );
                Console.WriteLine( "  <Decrypt>" );
                Console.WriteLine( "    -i InputFilePath\tEncrypted file path" );
                Console.WriteLine( "    -o OutputFilePath\tDecrypted file path (If empty, {InputFilePath} without '.fcrypt')" );
                Console.WriteLine( "    -p Password\t\tPassword (If empty, it will be prompted for input.)" );
                return 0;
            }

            if( string.IsNullOrEmpty( outputFilePath ) ) {
                outputFilePath = inputFilePath;
            }
            switch( encDec ) {
                case EncryptOrDecrypt.Encrypt:
                    inputFilePath = Path.GetFullPath( inputFilePath );
                    outputFilePath = !outputFilePath.EndsWith( ".fcrypt", StringComparison.CurrentCulture ) ? $"{Path.GetFullPath( outputFilePath )}.fcrypt" : Path.GetFullPath( outputFilePath );
                    break;
                case EncryptOrDecrypt.Decrypt:
                    inputFilePath = !inputFilePath.EndsWith( ".fcrypt", StringComparison.CurrentCulture ) ? $"{Path.GetFullPath( inputFilePath )}.fcrypt" : Path.GetFullPath( inputFilePath );
                    outputFilePath = outputFilePath.EndsWith( ".fcrypt", StringComparison.CurrentCulture ) ? Path.GetFullPath( $"./{Path.GetDirectoryName( outputFilePath )}/{Path.GetFileNameWithoutExtension( outputFilePath )}" ) : Path.GetFullPath( outputFilePath );
                    break;
            }

            if( !File.Exists( inputFilePath ) ) {
                Console.Error.WriteLine( $"[ERROR]: Input file not found: {inputFilePath}" );
                return 1;
            }
            if( File.Exists( outputFilePath ) ) {
                Console.WriteLine( $"Output file is aleady exists: {outputFilePath}" );
                Console.Write( "Overwrite? [Y]es/[N]o: " );
                if( Console.ReadLine().ToLower() != "y" ) {
                    Console.WriteLine( "Quit." );
                    return 0;
                }
            }

            while( string.IsNullOrEmpty( password ) ) {
                Console.Write( "Password: " );
                password = InputPassword();
                Console.WriteLine();
            }

            try {
                switch( encDec ) {
                    case EncryptOrDecrypt.Encrypt:
                        Console.WriteLine( $"Encrypting file: {inputFilePath}" );
                        FCrypt.Encrypt( inputFilePath, outputFilePath, password );
                        Console.WriteLine( $"Encrypted -> {outputFilePath}" );
                        break;
                    case EncryptOrDecrypt.Decrypt:
                        Console.WriteLine( $"Decrypting file: {inputFilePath}" );
                        FCrypt.Decrypt( inputFilePath, outputFilePath, password );
                        Console.WriteLine( $"Decrypted -> {outputFilePath}" );
                        break;
                }
            }
            catch( Exception ex ) {
                Console.WriteLine( $"Failed to {encDec.ToString()}." );
#if DEBUG
                Console.WriteLine( $"Message: {ex.Message}" );
                Console.WriteLine( $"Message: {ex.StackTrace}" );
#endif
            }

            return 0;
        }

        static readonly Regex cmdReg = new Regex( @"-[iopm]" );

        /// <summary>
        /// Parses command line argments.
        /// </summary>
        /// <param name="args">Command line argments</param>
        /// <returns></returns>
        static (EncryptOrDecrypt mode, string inputFilePath, string outputFilePath, string password) ParseCommand( string[] args ) {
            EncryptOrDecrypt mode = EncryptOrDecrypt.Unknown;
            string inputFilePath = null;
            string outputFilePath = null;
            string password = null;

            string argKey = "";
            for( int i = 0; i < args.Length; i++ ) {
                switch( args[i] ) {
                    case "-e":
                        if( mode == EncryptOrDecrypt.Unknown ) {
                            mode = EncryptOrDecrypt.Encrypt;
                        }
                        break;
                    case "-d":
                        if( mode == EncryptOrDecrypt.Unknown ) {
                            mode = EncryptOrDecrypt.Decrypt;
                        }
                        break;
                    case "-i":
                    case "-o":
                    case "-p":
                        argKey = args[i];
                        break;
                    default:
                        if( cmdReg.IsMatch( args[i] ) ) {
                            argKey = args[i].Substring( 0, 2 );
                            args[i] = args[i].Substring( 2, args[i].Length - 2 );
                        }
                        switch( argKey ) {
                            case "-i":
                                inputFilePath = args[i];
                                break;
                            case "-o":
                                outputFilePath = args[i];
                                break;
                            case "-p":
                                password = args[i];
                                break;
                        }
                        break;
                }
            }

            return ( mode, inputFilePath, outputFilePath, password );
        }

        /// <summary>
        /// Inputs a password from console.
        /// </summary>
        /// <returns></returns>
        static string InputPassword() {
            StringBuilder sb = new StringBuilder();
            while( true ) {
                var key = Console.ReadKey( true );
                if( key.Key == ConsoleKey.Enter ) {
                    break;
                }
                else if( key.Key == ConsoleKey.Backspace && sb.Length > 0 ) {
                    sb.Remove( sb.Length - 1, 1 );
                }
                else if( key.Key == ConsoleKey.Escape ) {
                    sb.Clear();
                }
                else {
                    sb.Append( key.KeyChar );
                }
            }

            return sb.ToString();
        }
    }
}

using System.Collections.Generic;
using System.Security.Cryptography;

namespace Lab7
{
    public enum EncryptAlgorithm
    {
        AES,
        Rijndael,
        DES,
        TripleDES,
        RC2
    }

    public static class Lab7Statics
    {
        public static Dictionary<CipherMode, string> EncodeType2Description = new Dictionary<CipherMode, string>
        {
            { CipherMode.ECB, "ECB - Electronic Code Block" },
            { CipherMode.CBC, "CBC - Cipher Block Chaining" },
            { CipherMode.OFB, "OFB - Output Feedback" },
            { CipherMode.CFB, "CFB - Cipher Feedback" },
            { CipherMode.CTS, "CTS - Cipher Text Stealing" }
        };
    }
}
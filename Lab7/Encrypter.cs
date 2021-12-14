using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Lab7
{
    public class Encrypter
    {
        private CipherMode _cipherMode;
        private PaddingMode _paddingMode;
        private EncryptAlgorithm _encryptAlgorithm;
        private bool _initVectorUsed;
        
        private SymmetricAlgorithm _symmetricAlgorithm;

        public event Action<EncryptAlgorithm> OnEncryptAlgorithmChanged = delegate {  };
        public event Action<CipherMode> OnCypherModeChanged = delegate {  };
        public event Action<byte[]> OnKeyUpdated = delegate {  };
        public event Action<byte[]> OnInitVectorChanged = delegate {  };
        public event Action<List<int>> OnKeyLengthListUpdate = delegate {  };
        public byte[] Key
        {
            get => _symmetricAlgorithm.Key;
            set => OnKeyUpdated(_symmetricAlgorithm.Key = value);
        }

        public void Init()
        {
            _cipherMode = CipherMode.CBC;
            _paddingMode = PaddingMode.None;
            
            ChangeAlgorithm(EncryptAlgorithm.AES);
        }
        
        public void ChangeAlgorithm(EncryptAlgorithm algorithm)
        {
            _encryptAlgorithm = algorithm;
            OnEncryptAlgorithmChanged(algorithm);
            
            _symmetricAlgorithm = GetSymmetricAlgorithm();
            
            var keyListLengths = LegalSizes();
            OnKeyLengthListUpdate(keyListLengths);
            
            ChangeKeyLength(keyListLengths.First());
        }

        public void ChangePaddingMode(PaddingMode paddingMode)
        {
            _paddingMode = paddingMode;
            _symmetricAlgorithm.Padding = _paddingMode;
        }

        public void ChangeCipherMode(CipherMode cipherMode)
        {
            _cipherMode = cipherMode;
            _symmetricAlgorithm.Mode = _cipherMode;
            
            OnCypherModeChanged(cipherMode);
        }

        public void ChangeKeyLength(int keyLength)
        {
            _symmetricAlgorithm.KeySize = keyLength;
            
            var blockSizes = LegalBlockSizes();
            int blockSize = 0;

            blockSize = blockSizes.Contains(_symmetricAlgorithm.KeySize) 
                ? _symmetricAlgorithm.KeySize 
                : blockSizes.First();

            _symmetricAlgorithm.BlockSize = blockSize;
            
            GenerateKey();
        }

        public void ChangeKey(string key)
        {
            if (!HexStringToBytes(key, out var bytes)) 
                return;
            
            _symmetricAlgorithm.Key = bytes;
            OnKeyUpdated(_symmetricAlgorithm.Key);
        }

        public void ChangeKey(byte[] key)
        {
            _symmetricAlgorithm.Key = key;
            OnKeyUpdated(_symmetricAlgorithm.Key);
        }
        
        public void GenerateKey()
        {
            _symmetricAlgorithm.GenerateKey();
            OnKeyUpdated(_symmetricAlgorithm.Key);

            GenerateInitVector();
        }

        public void GenerateInitVector()
        {
            if (_initVectorUsed)
            {
                _symmetricAlgorithm.GenerateIV();
                OnInitVectorChanged(_symmetricAlgorithm.IV);
            }
            else
            {
                // Zero IV
                var bytes = new byte[_symmetricAlgorithm.BlockSize / 8];
                _symmetricAlgorithm.IV = bytes;
                OnInitVectorChanged(bytes);
            }
        }

        public void ChangeInitVector(string initVector)
        {
            if (!HexStringToBytes(initVector, out var bytes)) 
                return;
            
            _symmetricAlgorithm.IV = bytes;
            OnInitVectorChanged(_symmetricAlgorithm.IV);
        }
        
        public void ShouldUseInitVector(bool initVectorUsed)
        {
            _initVectorUsed = initVectorUsed;
            
            GenerateInitVector();
        }

        public Task<byte[]> Encrypt(byte[] bytes)
        {
            var encryptor = _symmetricAlgorithm.CreateEncryptor();

            return Task.Run(() => encryptor.TransformFinalBlock(bytes, 0, bytes.Length));
        }

        public Task<byte[]> Decrypt(byte[] input)
        {
            byte[] outBytes;
            
            var decryptor = _symmetricAlgorithm.CreateDecryptor();
            return Task.Run(() => decryptor.TransformFinalBlock(input, 0, input.Length));
        }
        
        #region Encrypt algorithms
        
        private SymmetricAlgorithm GetSymmetricAlgorithm()
        {
            SymmetricAlgorithm CreateSymmetricAlgorithm()
            {
                switch (_encryptAlgorithm)
                {
                    case EncryptAlgorithm.AES: return Aes.Create();
                    case EncryptAlgorithm.Rijndael: return Rijndael.Create();
                    case EncryptAlgorithm.DES: return DES.Create();
                    case EncryptAlgorithm.TripleDES: return TripleDES.Create();
                    case EncryptAlgorithm.RC2: return RC2.Create();
                    default: return null;
                }
            }

            try
            {
                var symmetricAlgorithm = CreateSymmetricAlgorithm();
                symmetricAlgorithm.Mode = _cipherMode;
                symmetricAlgorithm.Padding = _paddingMode;
                return symmetricAlgorithm;
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error {e}");
                throw;
            }
        }

        #endregion

        public static double ShannonEntropy(byte[] s)
        {
            var map = new Dictionary<char, int>();
            foreach (var b in s)
            {
                var c = (char)b;
                if (!map.ContainsKey(c))
                    map.Add(c, 1);
                else
                    map[c] += 1;
            }

            double result = 0.0;
            int len = s.Length;
            foreach (var item in map)
            {
                var frequency = (double)item.Value / len;
                result -= frequency * (Math.Log(frequency) / Math.Log(2));
            }

            return result;
        }

        private List<int> LegalSizes()
        {
            var keys = new List<int>();
            
            foreach (KeySizes keySizes in _symmetricAlgorithm.LegalKeySizes)
            {
                if (keySizes.SkipSize == 0)
                {
                    keys.Add(keySizes.MaxSize);
                    continue;
                }
                
                for (int i = keySizes.MinSize; i <= keySizes.MaxSize; i += keySizes.SkipSize)
                {
                    keys.Add(i);
                }
            }

            return keys;
        }
        private List<int> LegalBlockSizes()
        {
            var blockSizes = new List<int>();
            
            foreach (KeySizes keySizes in _symmetricAlgorithm.LegalBlockSizes)
            {
                if (keySizes.SkipSize == 0)
                {
                    blockSizes.Add(keySizes.MaxSize);
                    continue;
                }
                
                for (int i = keySizes.MinSize; i <= keySizes.MaxSize; i += keySizes.SkipSize)
                {
                    blockSizes.Add(i);
                }
            }

            return blockSizes;
        }

        private bool HexStringToBytes(string str, out byte[] result)
        {
            try
            {
                var replace = str.Replace("-", string.Empty).Replace(" ", string.Empty);
                
                int numberChars = replace.Length;
                byte[] bytes = new byte[numberChars / 2];
                for (int i = 0; i < numberChars; i += 2)
                    bytes[i / 2] = Convert.ToByte(replace.Substring(i, 2), 16);
                
                result = bytes;
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Wrong key");
                result = null;
                return false;
            }
        }
    }
}
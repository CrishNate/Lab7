using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Windows.Controls;
using Microsoft.Win32;

namespace Lab7
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow
    {
        private Encrypter _encrypter;
        
        public MainWindow()
        {
            InitializeComponent();
            
            var encodeModesDesc = Lab7Statics.EncodeType2Description.Values.Select(x =>
            {
                var item = new ComboBoxItem
                {
                    Content = x
                };
                return item;
            }).ToList();
            
            EncodeModeComboBox.ItemsSource = encodeModesDesc;
            EncodeModeComboBox.SelectedItem = encodeModesDesc.First();
            
            _encrypter = new Encrypter();
            _encrypter.OnKeyUpdated += OnKeyLengthChanged;
            _encrypter.OnInitVectorChanged += OnInitVectorChanged;
            _encrypter.OnKeyLengthListUpdate += OnKeyLengthListUpdate;
            _encrypter.OnEncryptAlgorithmChanged += OnEncryptAlgorithmChanged;
            _encrypter.OnCypherModeChanged += OnCypherModeChanged;
            _encrypter.Init();

            var fillType = Enum.GetNames(typeof(PaddingMode));
            FillTypeComboBox.ItemsSource = fillType;
            FillTypeComboBox.SelectedItem = fillType.First();
            
            Dictionary<RadioButton, EncryptAlgorithm> _encryptAlgorithms =
                new Dictionary<RadioButton, EncryptAlgorithm>
                {
                    { AESRadioButton, EncryptAlgorithm.AES },
                    { RijndaelRadioButton, EncryptAlgorithm.Rijndael },
                    { DESRadioButton, EncryptAlgorithm.DES },
                    { TripleDESRadioButton, EncryptAlgorithm.TripleDES },
                    { RC2RadioButton, EncryptAlgorithm.RC2 }
                };

            foreach (KeyValuePair<RadioButton,EncryptAlgorithm> encryptAlgorithm in _encryptAlgorithms)
            {
                encryptAlgorithm.Key.Checked += (sender, args) => _encrypter.ChangeAlgorithm(encryptAlgorithm.Value);
            }
        }

        private void OnEncryptAlgorithmChanged(EncryptAlgorithm algorithm)
        {
            foreach (object o in EncodeModeComboBox.ItemsSource)
            {
                var item = o as ComboBoxItem;

                foreach (var cipherMode in new List<CipherMode>{CipherMode.OFB, CipherMode.CTS})
                {
                    if (Lab7Statics.EncodeType2Description[cipherMode] != item.Content)
                        continue;
                    
                    switch (algorithm)
                    {
                        case EncryptAlgorithm.AES:
                        case EncryptAlgorithm.Rijndael:
                            item.IsEnabled = false;

                            if (item.Content == (EncodeModeComboBox.SelectedItem as ComboBoxItem).Content)
                            {
                                _encrypter.ChangeCipherMode(CipherMode.CBC);
                            }

                            break;

                        case EncryptAlgorithm.DES:
                        case EncryptAlgorithm.TripleDES:
                        case EncryptAlgorithm.RC2:
                            item.IsEnabled = true;
                            break;
                    }
                }
            }
        }

        private void InputBrowseButtonClick(object sender, System.Windows.RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            bool? result = openFileDialog.ShowDialog();
            
            if (result.HasValue && result.Value)
            {
                InputTextBox.Text = openFileDialog.FileName;
                CalculateFile(InputTextBox, InputSizeInputText, InputEntropyInputText);
            }
        }

        private void OutputBrowseButtonClick(object sender, System.Windows.RoutedEventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            bool? result = saveFileDialog.ShowDialog();
            
            if (result.HasValue && result.Value)
            {
                OutTextBox.Text = saveFileDialog.FileName;
                CalculateFile(OutTextBox, OutSizeInputText, OutEntropyInputText);
            }
        }

        private void CalculateFile(TextBox inputTextBox, Label sizeText, Label entropyText)
        {
            if (FileSize(inputTextBox.Text, out var sizeStr))
                sizeText.Content = sizeStr;

            try
            {
                entropyText.Content = Encrypter.ShannonEntropy(File.ReadAllBytes(inputTextBox.Text));
            }
            catch (Exception exception)
            {
                entropyText.Content = sizeText.Content = "???";
            }
        }

        private void SaveButtonClick(object sender, System.Windows.RoutedEventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            bool? result = saveFileDialog.ShowDialog();

            if (result.HasValue && result.Value)
            {
                File.WriteAllBytes(saveFileDialog.FileName, _encrypter.Key);
            }
        }

        private void OpenButtonClick(object sender, System.Windows.RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            bool? result = openFileDialog.ShowDialog();
            
            if (result.HasValue && result.Value)
            {
                _encrypter.Key = File.ReadAllBytes(openFileDialog.FileName);
            }
        }

        private void KeyButtonClick(object sender, System.Windows.RoutedEventArgs e)
        {
            
            _encrypter.GenerateKey();
        }

        private void VectorButtonClick(object sender, System.Windows.RoutedEventArgs e)
        {
            _encrypter.GenerateInitVector();
        }

        private async void EncryptClick(object sender, System.Windows.RoutedEventArgs e)
        {
            try
            {
                var timeStamp = DateTime.Now;
                
                byte[] bytes = await _encrypter.Encrypt(File.ReadAllBytes(InputTextBox.Text));
                File.WriteAllBytes(OutTextBox.Text, bytes);
                
                CalculateFile(OutTextBox, OutSizeInputText, OutEntropyInputText);
                CalculationTimeText.Content = (DateTime.Now - timeStamp).ToString(@"hh\:mm\:ss\.ffff");
            }
            catch (Exception exception)
            {
                Console.WriteLine($"Error encrypt {exception}");
                CalculationTimeText.Content = $"Error {exception}";
            }
        }

        private async void DecryptClick(object sender, System.Windows.RoutedEventArgs e)
        {
            try
            {
                var timeStamp = DateTime.Now;
                
                byte[] bytes = await _encrypter.Decrypt(File.ReadAllBytes(InputTextBox.Text));
                File.WriteAllBytes(OutTextBox.Text, bytes);
                
                CalculateFile(OutTextBox, OutSizeInputText, OutEntropyInputText);
                CalculationTimeText.Content = (DateTime.Now - timeStamp).ToString(@"hh\:mm\:ss\.ffff");
            }
            catch (Exception exception)
            {
                Console.WriteLine($"Error decrypt {exception}");
                CalculationTimeText.Content = $"Error {exception}";
            }
        }

        private void AbortClick(object sender, System.Windows.RoutedEventArgs e)
        {

        }

        private bool FileSize(string filename, out string result)
        {
            var file = new FileInfo(filename);

            if (!file.Exists)
            {
                result = "";
                return false;
            }

            result = $"{new FileInfo(filename).Length.ToString()} byte(s)";
            return true;
        }

        private void OnKeyLengthChanged(byte[] bytes)
        {
            KeyTextBox.TextChanged -= KeyTextBox_TextChanged;
            KeyTextBox.Text = BitConverter.ToString(bytes);
            KeyTextBox.TextChanged += KeyTextBox_TextChanged;
        }
        
        private void OnInitVectorChanged(byte[] bytes)
        {
            VectorTextBox.TextChanged -= VectorTextBox_TextChanged;
            VectorTextBox.Text = BitConverter.ToString(bytes);
            VectorTextBox.TextChanged += VectorTextBox_TextChanged;
        }
        
        private void OnKeyLengthListUpdate(List<int> keyLengths)
        {
            KeyLengthInBitComboBox.ItemsSource = keyLengths;
            KeyLengthInBitComboBox.SelectedItem = keyLengths.First();
        }
        
        private void OnCypherModeChanged(CipherMode cipherMode)
        {
            EncodeModeComboBox.SelectionChanged -= EncodeModeComboBox_SelectionChanged;
            EncodeModeComboBox.Text = Lab7Statics.EncodeType2Description[cipherMode];
            EncodeModeComboBox.SelectionChanged += EncodeModeComboBox_SelectionChanged;
        }
        
        private void KeyLengthInBitComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (KeyLengthInBitComboBox.SelectedItem == null)
                return;
            
            _encrypter.ChangeKeyLength((int)KeyLengthInBitComboBox.SelectedItem);
        }

        private void EncodeModeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_encrypter == null)
                return;
            
            foreach (KeyValuePair<CipherMode, string> keyValuePair in Lab7Statics.EncodeType2Description)
            {
                if (keyValuePair.Value == EncodeModeComboBox.SelectedItem as string)
                {
                    _encrypter.ChangeCipherMode(keyValuePair.Key);
                }
            }
        }

        private void FillTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var paddingMode = (PaddingMode)Enum.Parse(typeof(PaddingMode), FillTypeComboBox.SelectedItem as string);
            _encrypter.ChangePaddingMode(paddingMode);
        }

        private void VectorCheckBox_ValueChanged(object sender, System.Windows.RoutedEventArgs e)
        {
            if (_encrypter == null)
                return;
            
            Debug.Assert(VectorCheckBox.IsChecked != null);
            
            _encrypter.ShouldUseInitVector(!VectorCheckBox.IsChecked.Value);
            VectorTextBox.IsReadOnly = !VectorCheckBox.IsChecked.Value;
        }

        private void KeyTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            _encrypter.ChangeKey(KeyTextBox.Text);
        }

        private void VectorTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            _encrypter.ChangeInitVector(VectorTextBox.Text);
        }

        private void PasswordButtonClick(object sender, System.Windows.RoutedEventArgs e)
        {
            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
            byte[] salt = new byte[24];
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(PasswordTextBox.Text, salt, 100000);
            var key = pbkdf2.GetBytes(_encrypter.Key.Length);

            _encrypter.ChangeKey(key);
        }
    }
}
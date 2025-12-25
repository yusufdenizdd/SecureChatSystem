using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using System;

namespace Guvenlik.CA
{
    public partial class MainWindow : Window
    {
        private CAServer _server;

        public MainWindow()
        {
            InitializeComponent();
        }

        // Butona tıklanınca çalışır
        public void BtnBaslat_Click(object sender, RoutedEventArgs e)
        {
            // Logları ekrana yazdırmak için bir fonksiyon tanımlıyoruz
            Action<string> logger = (message) =>
            {
                // Arayüz thread'inde güvenli şekilde çalıştır
                Dispatcher.UIThread.InvokeAsync(() =>
                {
                    var logBox = this.FindControl<TextBox>("txtLog");
                    logBox.Text += $"[{DateTime.Now.ToLongTimeString()}] {message}\n";
                });
            };

            try
            {
                _server = new CAServer(logger);
                _server.Start(5050); // 5050 Portundan başlat

                var btn = this.FindControl<Button>("btnBaslat");
                btn.IsEnabled = false; // İkinci kez basılmasın
                btn.Content = "Server Çalışıyor...";
            }
            catch (Exception ex)
            {
                logger("Hata: " + ex.Message);
            }
        }
    }
}
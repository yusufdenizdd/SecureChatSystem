using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using System;

namespace Guvenlik.Client
{
    public partial class MainWindow : Window
    {
        private ClientService _clientService;

        public MainWindow() { InitializeComponent(); }

        // Sistem Logları (Siyah kutu)
        private void SysLog(string message)
        {
            Dispatcher.UIThread.InvokeAsync(() =>
            {
                var log = this.FindControl<TextBox>("txtLog");
                log.Text += $"[{DateTime.Now.ToLongTimeString()}] {message}\n";
                log.CaretIndex = log.Text.Length; // En alta kaydır
            });
        }

        // Sohbet Logları (Beyaz kutu)
        private void ChatLog(string message)
        {
            Dispatcher.UIThread.InvokeAsync(() =>
            {
                var log = this.FindControl<TextBox>("txtChatHistory");
                log.Text += $"{message}\n";
                log.CaretIndex = log.Text.Length;
            });
        }

        private async void BtnGetCert_Click(object sender, RoutedEventArgs e)
        {
            var name = this.FindControl<TextBox>("txtMyName").Text;
            if (_clientService == null)
                _clientService = new ClientService(name, SysLog, ChatLog);

            await _clientService.GetCertificateFromCA("127.0.0.1", 5050);
        }

        private void BtnListen_Click(object sender, RoutedEventArgs e)
        {
            if (_clientService == null) { SysLog("Önce Sertifika!"); return; }
            int port = int.Parse(this.FindControl<TextBox>("txtMyPort").Text);
            _clientService.StartP2PServer(port);
        }

        private async void BtnConnect_Click(object sender, RoutedEventArgs e)
        {
            if (_clientService == null) { SysLog("Önce Sertifika!"); return; }
            int port = int.Parse(this.FindControl<TextBox>("txtTargetPort").Text);
            await _clientService.ConnectToPeer("127.0.0.1", port);
        }

        private async void BtnSend_Click(object sender, RoutedEventArgs e)
        {
            if (_clientService == null) return;
            var txtMsg = this.FindControl<TextBox>("txtMessage");
            string msg = txtMsg.Text;

            if (!string.IsNullOrEmpty(msg))
            {
                await _clientService.SendChatMessage(msg);
                txtMsg.Text = ""; // Kutuyu temizle
            }
        }
    }
}
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

        private void Log(string message)
        {
            Dispatcher.UIThread.InvokeAsync(() =>
            {
                var log = this.FindControl<TextBox>("txtLog");
                log.Text += $"[{DateTime.Now.ToLongTimeString()}] {message}\n";
            });
        }

        private async void BtnGetCert_Click(object sender, RoutedEventArgs e)
        {
            var name = this.FindControl<TextBox>("txtMyName").Text;
            if (_clientService == null) _clientService = new ClientService(name, Log);

            // CA Portu 5050 (Sabit)
            await _clientService.GetCertificateFromCA("127.0.0.1", 5050);
        }

        private void BtnListen_Click(object sender, RoutedEventArgs e)
        {
            if (_clientService == null) { Log("Önce Sertifika Almalısın!"); return; }
            int port = int.Parse(this.FindControl<TextBox>("txtMyPort").Text);
            _clientService.StartP2PServer(port);
        }

        private async void BtnConnect_Click(object sender, RoutedEventArgs e)
        {
            if (_clientService == null) { Log("Önce Sertifika Almalısın!"); return; }
            int port = int.Parse(this.FindControl<TextBox>("txtTargetPort").Text);
            await _clientService.ConnectToPeer("127.0.0.1", port);
        }
    }
}
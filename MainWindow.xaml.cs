using PacketDotNet;
using SharpPcap;
using SharpPcap.WinPcap;
using SoftSwitch.components;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Switch = SoftSwitch.components.Switch;

namespace SoftSwitch
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private Switch _switch;
        private ObservableCollection<CamTableGUI> _camTableRows;
        private bool _isSyslogEnabled;

        private void EnableSyslogButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_isSyslogEnabled)
            {
                try
                {
                    _switch.EnableSyslog(SyslogServerIpAddress.Text, SourceIpAddress.Text);
                    _isSyslogEnabled = true;
                    EnableSyslogButton.Content = "Disable Syslog";
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to enable Syslog: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            else
            {
                // Деактивуємо Syslog
                _switch.DisableSyslog();
                _isSyslogEnabled = false;
                EnableSyslogButton.Content = "Enable Syslog";
            }
        }
        public MainWindow()
        {
            InitializeComponent();
            _camTableRows = new ObservableCollection<CamTableGUI>();
            CamTable.ItemsSource = _camTableRows;
            StartWelcomeSequence();

        }

        private async void StartWelcomeSequence()
        {
            
            Storyboard fadeIn = (Storyboard)this.Resources["FadeInStoryboard"];
            fadeIn.Begin();
            await Task.Delay(5000);
            WelcomeText.Visibility = Visibility.Collapsed;
            AdditionalContentPanel.Visibility = Visibility.Visible;
            _switch = new Switch(StatsListBoxIn1,
                StatsListBoxOut1,
                StatsListBoxIn2,
                StatsListBoxOut2, AclRuleFor1, AclRuleFor2);
            _switch.OnAdaptersUpdated += OnAdaptersUpdated;
            _switch.OnPacketCaptured += OnPacketCaptured;
            _switch.OnPacketSender += OnPacketSender;
            _switch.UpdateMacTable += UpdateMacTable;
            _switch.OnSyslogMessage += (message) =>
            {
                this.Dispatcher.Invoke(() =>
                {
                    SyslogListBox.Items.Insert(0, message.ToString());
                });
            };
            if (_switch._devices.Count >= 2)
            {
                var mac1 = _switch._devices[0].MacAddress;
                var mac2 = _switch._devices[1].MacAddress;

                AclRuleFor1.ItemsSource = _switch.aclRules[mac1];
                AclRuleFor2.ItemsSource = _switch.aclRules[mac2];
            }

        }

        private void UpdateMacTable(Dictionary<PhysicalAddress, MACRow> dictionary)
        {
            this.Dispatcher.Invoke(() =>
            {
                _camTableRows.Clear();
                foreach (var row in dictionary)
                {
                    var tempRow = row.Value;
                    var elapsedTime = DateTime.Now - tempRow.LastUpdated;
                    var lifetimeSeconds = (int)(tempRow.AgingTime.TotalSeconds - elapsedTime.TotalSeconds);
                    lifetimeSeconds = Math.Max(0, lifetimeSeconds);

                    _camTableRows.Add(new CamTableGUI
                    {
                        MacAddress = tempRow.PhysicalAddress.ToString(),
                        AdapterName = _switch.GetPortNumber(tempRow.Device),
                        LifetimeSeconds = lifetimeSeconds
                    });
                    
                }
            });
        }
        private async void SetTtlButton_Click(object sender, RoutedEventArgs e)
        {
            Debug.WriteLine("Натиснуто кнопку Set TTL!");
            if (int.TryParse(TtlTextBox.Text, out int newTtlSeconds))
            {
                if (newTtlSeconds <= 0)
                {

                    return;
                }
                if (newTtlSeconds > 3600)
                {
                    return;
                }

                await _switch.GetCam().UpdateAllTtlAsync(newTtlSeconds);
                MessageBox.Show($"TTL updated to {newTtlSeconds} seconds for all MAC addresses.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("Please enter a valid number for TTL.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private void ClearCamButton_Click(object sender, RoutedEventArgs e)
        {

            _switch?.clearMac();
            
        }

        private void ResetStatsButton_Click(object sender, RoutedEventArgs e)
        {
            // Очищаємо ListBox-и
            StatsListBoxIn1.Items.Clear();
            StatsListBoxOut1.Items.Clear();
            StatsListBoxIn2.Items.Clear();
            StatsListBoxOut2.Items.Clear();

            // Скидаємо статистику в Switch
            _switch.ResetStatistics();

           
        }
        private void OnAdaptersUpdated(List<WinPcapDevice> devices)
        {
            this.Dispatcher.Invoke(() =>
            {

                var adapterList = new List<KeyValuePair<string, string>>();

                foreach (var device in devices)
                {
                    adapterList.Add(new KeyValuePair<string, string>(device.MacAddress.ToString(), device.Description));
                }

                AdaptersListBox.Items.Clear();
                foreach (var adapter in adapterList)
                {
                    AdaptersListBox.Items.Add($"{adapter.Key} - {adapter.Value}");
                }
            });
        }
        private void OnPacketCaptured(Packet packet)
        {
            this.Dispatcher.Invoke(() =>
            {
                if (packet is EthernetPacket ethPacket)
                {
                    string src = ethPacket.SourceHwAddress.ToString();
                    string dst = ethPacket.DestinationHwAddress.ToString();
                    string type = ethPacket.Type.ToString();

                        string packetInfo = $"Receive {src} → {dst} | {type}";

                        PacketsListBox.Items.Insert(0, packetInfo);
                    
                }
            });
        }
        private void OnPacketSender(Packet packet)
        {
            this.Dispatcher.Invoke(() =>
            {
                if (packet is EthernetPacket ethPacket)
                {
                    string src = ethPacket.SourceHwAddress.ToString();
                    string dst = ethPacket.DestinationHwAddress.ToString();
                    string type = ethPacket.Type.ToString();
                    string packetInfo = $"Send {src} → {dst} | {type}";

                    SenderPacketsListBox.Items.Insert(0, packetInfo);
                }
            });
        }
        private void AclRuleCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox checkBox)
            {
                var ruleDisplay = checkBox.DataContext as RuleAclDisplay;
                if (ruleDisplay == null) return;

                // Визначаємо, з якого ListBox викликано подію
                var listBox = FindAncestor<ListBox>(checkBox);
                if (listBox == null) return;

                var adapterIndex = listBox == AclRuleFor1 ? 0 : 1;
                var macAddress = _switch._devices[adapterIndex].MacAddress;
                var sourceIpTextBox = adapterIndex == 0 ? SourceIpAddress1 : SourceIpAddress2;
                var sourceMacTextBox = adapterIndex == 0 ? SourceMacAddress1 : SourceMacAddress2;

                // Визначаємо індекс правила
                var ruleIndex = listBox.Items.IndexOf(ruleDisplay);

                // Перевірка залежно від правила
                if (ruleIndex == 0) // Правило 1: Deny TCP (потрібна IP-адреса)
                {
                    if (!System.Net.IPAddress.TryParse(sourceIpTextBox.Text, out var ipAddress))
                    {
                        MessageBox.Show("Please enter a valid IP address.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Error);
                        checkBox.IsChecked = false; // Скасовуємо вибір
                        return;
                    }
                    // Оновлюємо IP-адресу в правилі
                    foreach (var rule in ruleDisplay.Rules)
                    {
                        rule.SourceIPAddress = ipAddress;
                    }
                }
                else if (ruleIndex == 1) // Правило 2: ICMP (потрібна MAC-адреса)
                {
                    if (!PhysicalAddress.TryParse(sourceMacTextBox.Text, out var macAddressParsed))
                    {
                        MessageBox.Show("Please enter a valid MAC address.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Error);
                        checkBox.IsChecked = false; // Скасовуємо вибір
                        return;
                    }
                    // Оновлюємо MAC-адресу в правилі
                    foreach (var rule in ruleDisplay.Rules)
                    {
                        rule.SourceMacAddress = macAddressParsed;

                    }
                }

                _switch.UpdateAclRules(macAddress, ruleDisplay.Rules, true);
            }
        }

        private void AclRuleCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            if (sender is CheckBox checkBox)
            {
                var ruleDisplay = checkBox.DataContext as RuleAclDisplay;
                if (ruleDisplay == null) return;

                // Визначаємо, з якого ListBox викликано подію
                var listBox = FindAncestor<ListBox>(checkBox);
                if (listBox == null) return;

                var adapterIndex = listBox == AclRuleFor1 ? 0 : 1;
                var macAddress = _switch._devices[adapterIndex].MacAddress;

                // Видаляємо правило з rulesIn або rulesOut
                _switch.UpdateAclRules(macAddress, ruleDisplay.Rules, false);
            }
        }

        // Допоміжний метод для пошуку батьківського ListBox
        private static T FindAncestor<T>(DependencyObject current) where T : DependencyObject
        {
            while (current != null)
            {
                if (current is T ancestor)
                    return ancestor;
                current = VisualTreeHelper.GetParent(current);
            }
            return null;
        }
        protected override void OnClosed(System.EventArgs e)
        {
            _switch.Stop();
            base.OnClosed(e);
        }
    }
}

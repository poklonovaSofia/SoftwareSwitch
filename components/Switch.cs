using PacketDotNet;
using SharpPcap;
using SharpPcap.WinPcap;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net;
using System.Net.Mail;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Controls;


namespace SoftSwitch.components
{
    public class Switch
    {
        private Receiver receiver1, receiver2;

        private Sender sender1, sender2;

        public List<WinPcapDevice> _devices = new();
        public Action<List<WinPcapDevice>> OnAdaptersUpdated;
        public event Action<Packet> OnPacketCaptured;
        public event Action<Packet> OnPacketSender;
        public event Action<Dictionary<PhysicalAddress, MACRow>> UpdateMacTable;
     
        private readonly Dictionary<PhysicalAddress, ProtocolsCountDictionary> _adapterStats = new();
        private readonly List<RuleAcl> allRules = new List<RuleAcl>();
        private readonly List<RuleAcl> rulesIn = new List<RuleAcl>(); 
        private readonly List<RuleAcl> rulesOut = new List<RuleAcl>();
        public readonly Dictionary<PhysicalAddress, ObservableCollection<RuleAclDisplay>> aclRules = new();
        private readonly Dictionary<WinPcapDevice, string> _portNumbers = new Dictionary<WinPcapDevice, string>();
        private CancellationTokenSource _cts = new();
        private readonly ListBox _statsListBoxIn1;
        private readonly ListBox _statsListBoxOut1;
        private readonly ListBox _statsListBoxIn2;
        private readonly ListBox _statsListBoxOut2;
        private readonly ListBox _aclRuleFor1;
        private readonly ListBox _aclRuleFor2;
        private readonly Cam cam = new Cam();
        private UdpClient? _udpClient;
        private IPEndPoint? _syslogServerEndPoint;
        private bool _syslogEnabled;
        public event Action<MessageSysLog> OnSyslogMessage;

        public void EnableSyslog(string syslogServerIp, string? sourceIp = null)
        {
            if (string.IsNullOrWhiteSpace(syslogServerIp))
            {
                throw new ArgumentException("Syslog Server IP address cannot be empty.");
            }

            // Парсимо IP-адресу Syslog-сервера
            if (!IPAddress.TryParse(syslogServerIp, out var serverIp))
            {
                throw new ArgumentException("Invalid Syslog Server IP address.");
            }

            // Створюємо кінцеву точку для Syslog-сервера (порт 514 — стандартний для Syslog)
            _syslogServerEndPoint = new IPEndPoint(serverIp, 514);

            // Якщо вказана IP-адреса джерела, прив’язуємо UdpClient до неї
            if (!string.IsNullOrWhiteSpace(sourceIp))
            {
                if (!IPAddress.TryParse(sourceIp, out var localIp))
                {
                    throw new ArgumentException("Invalid Source IP address.");
                }
                _udpClient = new UdpClient(new IPEndPoint(localIp, 0)); // Прив’язка до локальної IP
            }
            else
            {
                _udpClient = new UdpClient(); // Без прив’язки до конкретної IP
            }

            _syslogEnabled = true;
            Debug.WriteLine($"Syslog enabled. Sending messages to {syslogServerIp}:514");
        }
        public void DisableSyslog()
        {
            _syslogEnabled = false;
            _udpClient?.Close();
            _udpClient?.Dispose();
            _udpClient = null;
            _syslogServerEndPoint = null;
            Debug.WriteLine("Syslog disabled.");
        }

        public Cam GetCam()
        {
            return cam;
        }
        public Switch(
            ListBox statsListBoxIn1,
            ListBox statsListBoxOut1,
            ListBox statsListBoxIn2,
            ListBox statsListBoxOut2,
            ListBox aclRuleFor1,
            ListBox aclRuleFor2)
        {
            _statsListBoxIn1 = statsListBoxIn1;
            _statsListBoxOut1 = statsListBoxOut1;
            _statsListBoxIn2 = statsListBoxIn2;
            _statsListBoxOut2 = statsListBoxOut2;
            _aclRuleFor1 = aclRuleFor1;
            _aclRuleFor2 = aclRuleFor2;
            RuleAcl ruleAcl1 = new RuleAcl(AclAction.Deny, AclDirection.In, ProtocolType.TCP, PortOfProtocol.Http, null, AddressType.IP, null, null, AddressType.Any, null, null, false);
            RuleAcl ruleAcl2 = new RuleAcl(AclAction.Permit, AclDirection.Out, ProtocolType.ICMP, null, IcmpMessageType.EchoReply, AddressType.MAC, null, null, AddressType.Any, null, null, false);
            RuleAcl ruleAcl22 = new RuleAcl(AclAction.Deny, AclDirection.Out, ProtocolType.ICMP, null, IcmpMessageType.EchoRequest, AddressType.MAC, null, null, AddressType.Any, null, null, false);
            //RuleAcl ruleAcl3 = new RuleAcl(AclAction.Permit, AclDirection.In, ProtocolType.IP, null, null, AddressType.Any, null, null, AddressType.Any, null, null, false);
            //RuleAcl ruleAcl33 = new RuleAcl(AclAction.Permit, AclDirection.Out, ProtocolType.IP, null, null, AddressType.Any, null, null, AddressType.Any, null, null, false); ;
            allRules.Add(ruleAcl1);
            allRules.Add(ruleAcl22);
            allRules.Add(ruleAcl2);
            //allRules.Add(ruleAcl3);
            //allRules.Add(ruleAcl33);
            adp();
            UpdateAdapters();
            _cts = new CancellationTokenSource();
            Task.Run(() => MonitorAdapters(_cts.Token));
            cam.UpdateMacTableInSwitch += Cam_onMacRowRemove;
            cam.OnPortMove += (macAddress, oldDevice, newDevice) =>
            {
                var mes = new MessageSysLog(
                    DateTime.Now,
                    Facility.MAC,
                    Severity.Warning,
                    Mnemonic.PORT_MOVE,
                    $"MAC {macAddress} moved from {oldDevice.Description} to {newDevice.Description}"
                );
                LogSyslogMessage(mes);
            };
        }
        public void clearMac()
        {
            cam.clear();
        }
        private void Cam_onMacRowRemove()
        {
            UpdateMacTable?.Invoke(cam.getAllRows());
        }

    
        private async Task MonitorAdapters(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                adp(); // Перевіряємо адаптери
                cam.monitorExpired();
               //UpdateAdapters(); // Оновлюємо логіку програми
                try
                {
                    await Task.Delay(2000, token); // Чекаємо 2 секунди
                }
                catch (TaskCanceledException)
                {
                    Debug.WriteLine("🛑 Перевірка адаптерів зупинена.");
                    break;
                }
            }
        }
        private HashSet<string> _currentMacs = new HashSet<string>();
        public void ResetStatistics()
        {
            // Очищаємо статистику для всіх адаптерів
            _adapterStats.Clear();
            Debug.WriteLine("📊 Статистика адаптерів скинута.");
            foreach (var device in _devices)
            {
                Debug.WriteLine($"{device.Description} ({device.MacAddress})");
                if (!_adapterStats.ContainsKey(device.MacAddress))
                {
                    _adapterStats[device.MacAddress] = new ProtocolsCountDictionary();
                }
            }
            UpdateStatsUI();
        }
        private void adp()
        {
            // Отримуємо поточні активні адаптери за шаблоном
            var ethernetInterfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => Regex.IsMatch(ni.Name, @"^Ethernet") && ni.OperationalStatus == OperationalStatus.Up)
                .Select(ni => new
                {
                    Name = ni.Name,
                    MacAddress = ni.GetPhysicalAddress().ToString()
                })
                .ToList();

            // Формуємо список MAC-адрес нових адаптерів
            var newMacs = ethernetInterfaces.Select(ei => ei.MacAddress).ToHashSet();
            Debug.WriteLine("hii");
            // Порівнюємо з поточними MAC-адресами
            if (newMacs.SetEquals(_currentMacs) && _devices.Count == 2)
            {
                Debug.WriteLine("✅ Адаптери не змінилися, все стабільно.");
                return;
            }
           
            Debug.WriteLine("hii");
            
            // Якщо адаптерів менше 2, чекаємо, поки не з’являться нові
            if (ethernetInterfaces.Count < 2)
            {
                Debug.WriteLine($"⚠️ Знайдено {ethernetInterfaces.Count} активних адаптерів. Потрібно 2. Чекаємо...");
                UpdateAdapters();
                return;
            }
            if (_devices.Count > 0)
            {
                Debug.WriteLine("🛑 Зміна в адаптерах! Зупиняємо поточні...");
                receiver1?.Stop();
                receiver2?.Stop();
                sender1?.Stop();
                sender2?.Stop();
                receiver1 = null;
                receiver2 = null;
                sender1 = null;
                sender2 = null;

                foreach (var device in _devices)
                {
                    if (device.Opened)
                    {
                        device.Close();
                        Debug.WriteLine($"🛑 Адаптер {device.Name} закрито.");
                    }
                }
                _devices.Clear();
                
            }

            // Знайшли 2 або більше адаптерів, оновлюємо список
            var allDevices = WinPcapDeviceList.New(); // Оновлюємо список пристроїв
            var matchedDevices = new List<WinPcapDevice>();

            foreach (var ethernet in ethernetInterfaces)
            {
                WinPcapDevice matchingDevice = null;
                foreach (var device in allDevices)
                {
                    try
                    {
                        if (!device.Opened) device.Open(OpenFlags.Promiscuous | OpenFlags.NoCaptureLocal, 1);
                        if (device.MacAddress != null && device.MacAddress.ToString() == ethernet.MacAddress)
                        {
                            matchingDevice = device;
                            Debug.WriteLine($"✅ Знайдено збіг: {device.Name} | MAC: {device.MacAddress}");
                            break;
                        }
                        if (!device.Opened) device.Close();
                    }
                    catch (DeviceNotReadyException ex)
                    {
                        Debug.WriteLine($"❌ Пристрій {device.Name} не готовий: {ex.Message}");
                        if (device.Opened) device.Close();
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"❌ Помилка при роботі з пристроєм {device.Name}: {ex.Message}");
                        if (device.Opened) device.Close();
                    }
                }

                if (matchingDevice != null)
                {
                    matchedDevices.Add(matchingDevice);
                    if (matchedDevices.Count == 2) break;
                }
            }

            if (matchedDevices.Count == 2)
            {
               // _devices.Clear();
                _devices.AddRange(matchedDevices);
                _currentMacs = newMacs; // Оновлюємо список MAC-адрес
                UpdateAdapters();
                Debug.WriteLine("✅ Знайдено 2 нові адаптери, оновлюємо...");
            }
            else
            {
                Debug.WriteLine($"⚠️ Знайдено {matchedDevices.Count} адаптерів. Потрібно 2. Чекаємо...");
            }
        }
        private void UpdateAdapters()
        {


            Debug.WriteLine("Update list adapters:");
            foreach (var device in _devices)
            {
                Debug.WriteLine($"{device.Description} ({device.MacAddress})");
                if (!_adapterStats.ContainsKey(device.MacAddress))
                {
                    _adapterStats[device.MacAddress] = new ProtocolsCountDictionary();
                }

                if (!aclRules.ContainsKey(device.MacAddress))
                {
                    var displayRules = new ObservableCollection<RuleAclDisplay>
                    {
                        new RuleAclDisplay(new List<RuleAcl> { allRules[0] }), // Deny TCP
                        new RuleAclDisplay(new List<RuleAcl> { allRules[1], allRules[2] }), // ICMP (Echo Request + Echo Reply)
                        new RuleAclDisplay(new List<RuleAcl> { allRules[3], allRules[4] }) // Permit (In + Out)
                    };
                    aclRules[device.MacAddress] = displayRules;
                }
            }
            UpdateAclRulesUI();
            OnAdaptersUpdated?.Invoke(_devices);

            if (_devices.Count >= 2) 
            {

                var device1 = _devices.FirstOrDefault();
                var device2 = _devices.Skip(1).FirstOrDefault();
                if (sender1 == null && device1 != null)
                {
                    if (!device1.Opened)
                    {
                        device1.Open(OpenFlags.Promiscuous | OpenFlags.NoCaptureLocal, 1);
                        Debug.WriteLine($"🛑 Open");
                    }
                    sender1 = new Sender(device1, rulesOut);
                    Debug.WriteLine($"🛑 Оновлюю сендер1");
                   

                    sender1.OnPacketSend += packet => HandlePacketSent(packet, device1);
                    sender1.OnSendFailed += (device, macAddress) => 
                    {
                        Task.Run(async () => 
                        {
                            await cam.UpdateTtlForDeviceAsync(device, 10);
                            
                            
                        });
                        if (macAddress != null)
                        {
                            _adapterStats.Remove(macAddress);
                            aclRules.Remove(macAddress);
                        }

                        _portNumbers.Remove(device);
                        if (sender1?.device == device)
                        {
                            sender1 = null;
                        }
                        if (receiver1?._device == device)
                        {
                            receiver1.Stop();
                            receiver1 = null;
                        }
                        
                        _devices.Remove(device);
                        var updatedSenders = new List<Sender> { sender1, sender2 }.Where(s => s != null).ToList();

                        if (receiver1 != null)
                        {
                            receiver1.UpdateSenders(updatedSenders);
                        }
                        if (receiver2 != null)
                        {
                            receiver2.UpdateSenders(updatedSenders);
                        }
                        var mes = new MessageSysLog(DateTime.Now, Facility.HARDWARE, Severity.Critical, Mnemonic.PORT_DIS, $"Adapter {macAddress} is disconnected");
                        LogSyslogMessage(mes);
                        OnAdaptersUpdated?.Invoke(_devices);
                        UpdateStatsUI();
                        Debug.WriteLine($"🗑️ Статистика очищена для {device.Description}, TTL встановлено на 10 секунд.");

                    };
                }
                if (sender2 == null && device2 != null)
                {
                    if (!device2.Opened)
                    {
                        device1.Open(OpenFlags.Promiscuous | OpenFlags.NoCaptureLocal, 1);
                        Debug.WriteLine($"🛑 Open");
                    }
                    Debug.WriteLine($"🛑 Оновлюю сендер2");
                    sender2 = new Sender(device2, rulesOut);

                    sender2.OnPacketSend += packet => HandlePacketSent(packet, device2);
                    sender2.OnSendFailed += (device, macAddress) => 
                    {

                        Task.Run(async () =>
                        {
                            Debug.WriteLine($"🛑 Адаптер {device.Description} відключений. Видаляємо його звідусіль...");
                            await cam.UpdateTtlForDeviceAsync(device, 10); 

                           
                        });
  
                        if (macAddress != null)
                        {
                            _adapterStats.Remove(macAddress);
                            aclRules.Remove(macAddress);
                        }

                        _portNumbers.Remove(device);

                        if (sender2?.device == device)
                        {
                            sender2 = null;
                        }
                        if (receiver2?._device == device)
                        {
                            receiver2.Stop();
                            receiver2 = null;
                        }
                        
                        _devices.Remove(device);
                        var updatedSenders = new List<Sender> { sender1, sender2 }.Where(s => s != null).ToList();

                        if (receiver1 != null)
                        {
                            receiver1.UpdateSenders(updatedSenders);
                        }
                        if (receiver2 != null)
                        {
                            receiver2.UpdateSenders(updatedSenders);
                        }
                        var mes = new MessageSysLog(DateTime.Now, Facility.HARDWARE, Severity.Critical, Mnemonic.PORT_DIS, $"Adapter {macAddress} is disconnected");
                        LogSyslogMessage(mes);
                        OnAdaptersUpdated?.Invoke(_devices);
                        UpdateStatsUI();

                        Debug.WriteLine($"🗑️ Адаптер {device.Description} повністю видалений.");
                        

                    };
                }
                var senders = new List<Sender> { sender1, sender2 }.Where(s => s != null).ToList();

                _portNumbers.Clear();
                for (int i = 0; i < _devices.Count; i++)
                {
                    _portNumbers[_devices[i]] = $"Port {i + 1}";
                }

                if (receiver1 == null && device1 != null)
                {
                    Debug.WriteLine($"🛑 Оновлюю ресівер1");
                    receiver1 = new Receiver(device1, senders, cam, rulesIn);
                    receiver1.OnSyslogMessage += LogSyslogMessage;
                    receiver1.OnPacketReceived += packet => HandlePacketReceived(packet, _devices.FirstOrDefault(d => d == device1));
                    receiver1.Start();
                    Debug.WriteLine($"🎧 Receiver 1 активований для {device1.Description}");
                }
                else
                {
                    receiver1.UpdateSenders(senders);
                }

                if (receiver2 == null && device2 != null)
                {
                    Debug.WriteLine($"🛑 Оновлюю ресівер2");
                    receiver2 = new Receiver(device2, senders, cam, rulesIn);
                    receiver2.OnSyslogMessage += LogSyslogMessage;
                    receiver2.OnPacketReceived += packet => HandlePacketReceived(packet, _devices.FirstOrDefault(d => d == device2));
                    receiver2.Start();
                    Debug.WriteLine($"🎧 Receiver 2 активований для {_devices[1].Description}");
                }
                else
                {
                    receiver2.UpdateSenders(senders);
                }
            }
            else
            {
                Console.WriteLine("Не вистачає адаптерів для світча. Потрібно 2 адаптери.");
            }
            UpdateStatsUI();
        }
        private void LogSyslogMessage(MessageSysLog message)
        {

            OnSyslogMessage?.Invoke(message);

            // Відправляємо через UDP, якщо Syslog активовано
            if (_syslogEnabled && _udpClient != null && _syslogServerEndPoint != null)
            {
                try
                {
                    var messageBytes = Encoding.UTF8.GetBytes(message.ToString());
                    _udpClient.Send(messageBytes, messageBytes.Length, _syslogServerEndPoint);
                    Debug.WriteLine($"Syslog message sent: {message}");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Failed to send Syslog message: {ex.Message}");
                }
            }
        }
        public void UpdateAclRules(PhysicalAddress macAddress, List<RuleAcl> rules, bool add)
        { 
            Debug.WriteLine(macAddress.ToString());
            
            foreach (var rule in rules)
            {
                Debug.WriteLine(rule.Description);
                if (rule.Direction == AclDirection.In)
                {
                    if (add)
                    {
                        if (!rulesIn.Contains(rule))
                            rulesIn.Add(rule);
                    }
                    else
                    {
                        rulesIn.Remove(rule);
                    }
                }
                else if (rule.Direction == AclDirection.Out)
                {
                    if (add)
                    {
                        if (!rulesOut.Contains(rule))
                            rulesOut.Add(rule);
                    }
                    else
                    {
                        rulesOut.Remove(rule);
                    }
                }
            }

            // Оновлюємо Receiver і Sender
            if (receiver1?._device.MacAddress.Equals(macAddress) == true)
            {
                receiver1.UpdateRules(rulesIn);
            }
            if (receiver2?._device.MacAddress.Equals(macAddress) == true)
            {
                receiver2.UpdateRules(rulesIn);
            }
            if (sender1?.device.MacAddress.Equals(macAddress) == true)
            {
                sender1.UpdateRules(rulesOut);
            }
            if (sender2?.device.MacAddress.Equals(macAddress) == true)
            {
                sender2.UpdateRules(rulesOut);
            }
        }

        public string GetPortNumber(WinPcapDevice device)
        {
            return _portNumbers.TryGetValue(device, out var portNumber) ? portNumber : "Unknown Port";
        }
        public Dictionary<WinPcapDevice,string> GetPortNumbers()
        {
            return _portNumbers;
        }
        private void HandlePacketReceived(Packet packet, WinPcapDevice device)
        {
            if (device == null)
            {
                Debug.WriteLine("⚠️ Адаптер не знайдений у списку _devices. Пропускаємо обробку пакета.");
                return;
            }
            OnPacketCaptured?.Invoke(packet);
            UpdatePacketStats(packet, device.MacAddress, "in");
            var ethernetPacket = packet as EthernetPacket;
            if (ethernetPacket == null) return;
            cam.addRowOrUpdate(ethernetPacket.SourceHwAddress, device);
        }

        private void HandlePacketSent(Packet packet, WinPcapDevice device)
        {
            OnPacketSender?.Invoke(packet);
            UpdatePacketStats(packet, device.MacAddress, "out");
            var ethernetPacket = packet as EthernetPacket;
            if (ethernetPacket == null) return;
            cam.addRowOrUpdate(ethernetPacket.DestinationHwAddress, device);
        }
       
        private void UpdatePacketStats(Packet packet, PhysicalAddress adapterMac, string direction)
        {
            var ethernetPacket = packet as EthernetPacket;
            if (ethernetPacket == null) return;

            var stats = _adapterStats[adapterMac].Stats;
            // string protocol;
            stats["Ethernet"][direction]++;
            switch (ethernetPacket.Type)
            {
                 
                case EthernetPacketType.Arp:
                    stats["ARP"][direction]++;
                    break;

                case EthernetPacketType.IpV4:
                    // Враховуємо IPv4 для всіх пакетів цього типу
                    stats["IPv4"][direction]++;

                    // Перевіряємо верхній рівень (якщо є)
                    var ipPacket = ethernetPacket.Extract(typeof(IPv4Packet)) as IPv4Packet;
                    if (ipPacket != null)
                    {
                        if (ipPacket.Protocol == IPProtocolType.ICMP)
                            stats["ICMP"][direction]++;
                        else if (ipPacket.Protocol == IPProtocolType.TCP)
                        {
                            stats["TCP"][direction]++;
                            var tcpPacket = ipPacket.Extract(typeof(TcpPacket)) as TcpPacket;
                            if (tcpPacket != null)
                            {
                                /*
                                 * if (tcpPacket.DestinationPort == 80 || tcpPacket.SourcePort == 80 ||
                                        tcpPacket.DestinationPort == 443 || tcpPacket.SourcePort == 443)
                                        {
                                             stats["HTTP"][direction]++;
                                        }
                                 */
                                Debug.Write($"port dst {tcpPacket.DestinationPort} and src {tcpPacket.SourcePort}");
                                byte[] payload = tcpPacket.PayloadData;
                                if (payload != null && payload.Length > 0)
                                {
  
                                    string payloadString = System.Text.Encoding.ASCII.GetString(payload.Take(10).ToArray());
                                    Debug.Write(payloadString);
                                    if (payloadString.StartsWith("GET") ||
                                        payloadString.StartsWith("POST") ||
                                        payloadString.StartsWith("PUT") ||
                                        payloadString.StartsWith("HEAD") ||
                                        payloadString.StartsWith("HTTP/1."))
                                    {
                                        stats["HTTP"][direction]++;
                                    }
                                }
                            }
                        }    
                        else if (ipPacket.Protocol == IPProtocolType.UDP)
                            stats["UDP"][direction]++;
     
                    }
                    break;

                case EthernetPacketType.IpV6:
                    stats["IPv6"][direction]++;

                    break;

                default:
                    return; // Ігноруємо невідомі протоколи
            }

            //stats[protocol][direction]++;
            UpdateStatsUI();
        }
        private void UpdateStatsUI()
        {
            _statsListBoxIn1.Dispatcher.Invoke(() =>
            {
                if (_devices.Count >= 1 && _devices[0].Opened)
                {
                    var stats1 = _adapterStats[_devices[0].MacAddress].Stats;
                    _statsListBoxIn1.Items.Clear();
                    _statsListBoxOut1.Items.Clear();
                    foreach (var protocol in stats1)
                    {
                        _statsListBoxIn1.Items.Add($"{protocol.Key}: {protocol.Value["in"]}");
                        _statsListBoxOut1.Items.Add($"{protocol.Key}: {protocol.Value["out"]}");
                    }
                }

                if (_devices.Count >= 2 && _devices[1].Opened)
                {
                    var stats2 = _adapterStats[_devices[1].MacAddress].Stats;
                    _statsListBoxIn2.Items.Clear();
                    _statsListBoxOut2.Items.Clear();
                    foreach (var protocol in stats2)
                    {
                        _statsListBoxIn2.Items.Add($"{protocol.Key}: {protocol.Value["in"]}");
                        _statsListBoxOut2.Items.Add($"{protocol.Key}: {protocol.Value["out"]}");
                    }
                }
            });
        }
        private void UpdateAclRulesUI()
        {
            _aclRuleFor1.Dispatcher.Invoke(() =>
            {
                if (_devices.Count >= 1 && _devices[0].Opened)
                {
                    var mac1 = _devices[0].MacAddress;
                    _aclRuleFor1.ItemsSource = aclRules.ContainsKey(mac1) ? aclRules[mac1] : null;
                }
                else
                {
                    _aclRuleFor1.ItemsSource = null;
                }

                if (_devices.Count >= 2 && _devices[1].Opened)
                {
                    var mac2 = _devices[1].MacAddress;
                    _aclRuleFor2.ItemsSource = aclRules.ContainsKey(mac2) ? aclRules[mac2] : null;
                }
                else
                {
                    _aclRuleFor2.ItemsSource = null;
                }
            });
        }
        public void Stop()
        {
            //_monitor.StopMonitoring();
            receiver1?.Stop();
            receiver2?.Stop();
            sender1?.Stop();
            sender2?.Stop();
        }
       
        public void startWork()
        {

        }
    }
}

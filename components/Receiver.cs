using System;
using System.Threading;
using SharpPcap;
using PacketDotNet;
using System.Diagnostics;
using System.Net.Sockets;
using SharpPcap.WinPcap;
using System.Windows.Input;

namespace SoftSwitch.components
{
    public class Receiver
    {
        public WinPcapDevice _device;

        public event Action<Packet> OnPacketReceived;
        private volatile bool _isRunning = false;
        private  List<Sender> _senders;
        private  List<RuleAcl> rulesIn;
        private readonly Cam cam;
        public event Action<MessageSysLog> OnSyslogMessage;
        public Receiver(WinPcapDevice device, List<Sender> senders, Cam _cam, List<RuleAcl> _rulesIn)
        {
            _device = device;
            _senders = senders ?? throw new ArgumentNullException(nameof(senders));
            cam = _cam;
            rulesIn = _rulesIn;
            
        }
        public void Start()
        {
            try
            {
                _device.OnPacketArrival +=
                new PacketArrivalEventHandler(PacketHandler);
                _device.StartCapture();
                _isRunning = true;
                Debug.WriteLine($"📡 Прослуховування адаптера: {_device.Description} (MAC: {_device.MacAddress})");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Помилка при запуску Receiver: {ex.Message}");
            }
        }

        public void Stop()
        {
            try
            {
                _isRunning = false; 
                _device?.Close();  
                Debug.WriteLine($"🛑 Receiver зупинено для {_device?.Description}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Помилка при зупинці Receiver: {ex.Message}");
            }
        }
        public void UpdateRules(List<RuleAcl> newRules)
        {
            rulesIn = new List<RuleAcl>(newRules);
        }

        private void PacketHandler(object sender, CaptureEventArgs e)
        {
            if (!_isRunning) return;
            var rawPacket = e.Packet;
            if (rawPacket.LinkLayerType != PacketDotNet.LinkLayers.Ethernet) return;


            if (rawPacket.Data == null || rawPacket.Data.Length < 14) 
            {
                Debug.WriteLine($"⚠️ Некоректний пакет: Data is null or too short (Length: {rawPacket.Data?.Length ?? 0}). Пропускаємо...");
                return;
            }

            EthernetPacket ethernetPacket = null;
            try
            {
                var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                ethernetPacket = packet as EthernetPacket;
                if (ethernetPacket == null)
                {
                    Debug.WriteLine($"⚠️ Не вдалося розпарсити пакет як EthernetPacket. Пропускаємо...");
                    return;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Помилка при парсингу пакета: {ex.Message}. Пропускаємо...");
                return;
            }
            foreach (var rule in rulesIn)
            {
                if (ethernetPacket.Type == EthernetPacketType.IpV4)
                {
                    var ipPacket = ethernetPacket.Extract(typeof(IPv4Packet)) as IPv4Packet;
                    if (ipPacket.Protocol == IPProtocolType.TCP && rule.Protocol == ProtocolType.TCP)
                    {
                        var tcpPacket = ipPacket.Extract(typeof(TcpPacket)) as TcpPacket;
                        if (tcpPacket == null) continue;
                        if (ipPacket.SourceAddress.Equals(rule.SourceIPAddress))
                        {

                            if (rule.PortOfProtocol.HasValue && tcpPacket.DestinationPort == (int)rule.PortOfProtocol)
                            {
                                if (rule.Action == AclAction.Deny)
                                {
                                    var syslogMessage = new MessageSysLog(DateTime.Now, Facility.ACL, Severity.Error, Mnemonic.ACL_DROP, $"Packet dropped by ACL rule: {rule.Description}");
                                    OnSyslogMessage?.Invoke(syslogMessage); 
                                    return;
                                }
                            }
                        }
                    }
                    
                }
                
            }

            OnPacketReceived?.Invoke(ethernetPacket);
          
            SendPacketToTargetAdapter(ethernetPacket, (ICaptureDevice)sender);
        }
        public void UpdateSenders(List<Sender> senders)
        {
            _senders = senders ?? throw new ArgumentNullException(nameof(senders));
            Debug.WriteLine($"📋 Оновлено список Sender-ів для Receiver на {_device.Description}. Новий розмір: {_senders.Count}");
        }
        private void SendPacketToTargetAdapter(EthernetPacket ethernetPacket, ICaptureDevice sourceDevice)
        {
            // Перевірка на null для пакета
            if (ethernetPacket == null)
            {
                Debug.WriteLine("❌ Отримано null-пакет, пропускаємо.");
                return;
            }
           
            if (_senders.Count == 1) return;
            
            var destinationMac = ethernetPacket.DestinationHwAddress;
            if (destinationMac == null)
            {
               // Debug.WriteLine("❌ MAC-адреса призначення null, пропускаємо.");
                return;
            }

    
            string destMacString = destinationMac.ToString();
            bool isBroadcastOrMulticast = destMacString == "FFFFFFFFFFFF" || destMacString.StartsWith("01005E");

            if (isBroadcastOrMulticast)
            {
                //Debug.WriteLine("📢 Broadcast/Multicast пакет отримано! Розсилаємо всім адаптерам...");
            }
            else
            {
                // Перевіряємо, чи є MAC-адреса в таблиці Cam
                var targetDevice = cam.existMac(destinationMac);
                if (targetDevice != null)
                {
                 
                    if (targetDevice == sourceDevice)
                    {
                       // Debug.WriteLine($"🛑 Цільова MAC-адреса {destinationMac} прив’язана до джерела {sourceDevice.Description}, пакет відкинуто.");
                        return;
                    }
                    // Шукаємо Sender для цільового адаптера
                    var targetSender = _senders.FirstOrDefault(s => s != null && s.device == targetDevice);
                    if (targetSender != null)
                    {
                        targetSender.SendPacket(ethernetPacket);
                       // Debug.WriteLine($"📤 Unicast відправлено на {targetSender.device.Description} (MAC: {destinationMac})");
                        return; // Пакет відправлено, виходимо
                    }
                    else
                    {
                     //   Debug.WriteLine($"⚠️ Не знайдено Sender для адаптера {targetDevice.Description}, розсилаємо всім...");
                    }
                }
                else
                {
                    //Debug.WriteLine($"❓ Невідомий MAC {destinationMac}, розсилаємо всім...");
                }
            }

            // Відправляємо пакет усім адаптерам, крім джерела (для broadcast/multicast або невідомого MAC)
            foreach (var sender in _senders)
            {
                if (sender != null && sender.device != sourceDevice)
                {
                    sender.SendPacket(ethernetPacket);
                   // Debug.WriteLine($"📢 Відправлено на {sender.device.Description}");
                }
            }
        }

    }
}
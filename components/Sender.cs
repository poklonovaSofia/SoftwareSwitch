using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using SharpPcap.WinPcap;
using System.Text;
using System.Threading.Tasks;


namespace SoftSwitch.components
{
    public class Sender
    {
        public WinPcapDevice device { get; }
        private List<RuleAcl> rulesOut;
        public event Action<Packet> OnPacketSend;
        private bool _isOpen = false;
        private readonly PhysicalAddress _macAddress;
        public event Action<MessageSysLog> OnSyslogMessage;

        public event Action<WinPcapDevice, PhysicalAddress> OnSendFailed;
        public Sender(WinPcapDevice device, List<RuleAcl> _rulesOut)
        {
            
            this.device = device;
            _macAddress = device.MacAddress;
            rulesOut = _rulesOut;

        }
        public void UpdateRules(List<RuleAcl> newRules)
        {
            rulesOut = new List<RuleAcl>(newRules);
        }
        public void SendPacket(EthernetPacket packet)
        {
            try
            {
                foreach (var rule in rulesOut)
                {
                    if (rule.SourceAddressType == AddressType.MAC && rule.SourceMacAddress != null)
                    {
                        if (!packet.SourceHwAddress.Equals(rule.SourceMacAddress))
                            continue; 
                    }
                    if (packet.Type == EthernetPacketType.IpV4)
                    {
                        var ipPacket = packet.Extract(typeof(IPv4Packet)) as IPv4Packet;
                        if (ipPacket == null) continue;

                        if (ipPacket.Protocol == IPProtocolType.ICMP && rule.Protocol == ProtocolType.ICMP)
                        {
                            var icmpPacket = ipPacket.Extract(typeof(ICMPv4Packet)) as ICMPv4Packet;
                            if (icmpPacket == null) continue;
                            if (icmpPacket.Header.Length < 2)
                            {
                                Debug.WriteLine("⚠️ Некоректний ICMP-пакет: Заголовок занадто короткий.");
                                continue;
                            }

                            byte icmpType = icmpPacket.Header[0]; 

                            if (rule.IcmpType.HasValue && icmpType == (byte)rule.IcmpType)
                            {
                                if (rule.Action == AclAction.Deny)
                                {
                                    var mes = new MessageSysLog(DateTime.Now, Facility.ACL, Severity.Error, Mnemonic.ACL_DROP, $"Packet dropped by ACL rule: {rule.Description})");
                                    OnSyslogMessage?.Invoke(mes);
                                    Debug.WriteLine($"Packet dropped by rule (Out): {rule.Description}");
                                    return; 
                                }
                 
                            }
                        }
                    }
                }
                device.SendPacket(packet);
                _isOpen = false;
                var mes = new MessageSysLog(DateTime.Now, Facility.SYS, Severity.Informational, Mnemonic.PKT_SENT, $"Packet sent from {packet.SourceHwAddress}");
                OnSyslogMessage?.Invoke(mes);
       
                OnPacketSend?.Invoke(packet);
            }
            catch (Exception ex)
            {
                if (!_isOpen)
                {
                    OnSendFailed?.Invoke(device, _macAddress);
                    device.Close();
                    
                    _isOpen = true;
                }
                //Debug.WriteLine($"❌ Помилка при відправці пакета через {device.Description}: {ex.Message}");


            }
        }

        public bool IsTarget(PhysicalAddress mac)
        {
            return device.MacAddress.Equals(mac);
        }
        public void Start()
        {
            try
            {
                if (!_isOpen)
                {
                    device.Open(OpenFlags.Promiscuous | OpenFlags.NoCaptureLocal, 1000);
                    _isOpen = true;
                    Debug.WriteLine($"📡 Sender відкрито для {device.Description}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Помилка при відкритті Sender: {ex.Message}");
            }
        }
        public void Stop()
        {
            try
            {
                //f (_isOpen)
                //{
                  device.Close();
                    //_isOpen = false;
                    Debug.WriteLine($"🛑 Sender зупинено для {device.Description}");
                //}
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"❌ Помилка при зупинці Sender: {ex.Message}");
            }
        }
    }
}

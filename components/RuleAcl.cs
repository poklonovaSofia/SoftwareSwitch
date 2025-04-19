using System.Net;
using System.Net.NetworkInformation;


namespace SoftSwitch.components
{
    public enum AclAction
    {
        Permit,
        Deny
    }

    public enum AclDirection
    {
        In,
        Out,
        Any
    }

    public enum AddressType
    {
        IP,
        MAC,
        Any
    }

    public enum ProtocolType
    {
        TCP,
        ICMP,
        IP,
        Any,
        UDP
    }
  

    public enum IcmpMessageType
    {
        EchoReply = 0,
        EchoRequest = 8
    }
    public enum PortOfProtocol
    {
        Http = 80,

        Any
    }

    public class RuleAcl
    {
        public AclAction Action { get; set; }
        public AclDirection Direction { get; set; }
        public ProtocolType Protocol { get; set; }
        public IcmpMessageType? IcmpType { get; set; }
        public PortOfProtocol? PortOfProtocol { get; set; } 
       
        public AddressType SourceAddressType { get; set; }
        public IPAddress? SourceIPAddress { get; set; } 
        public PhysicalAddress? SourceMacAddress { get; set; }      
        public AddressType DestinationAddressType { get; set; } 
        public IPAddress? DestinationIPAddress { get; set; }
        public PhysicalAddress? DestinationMacAddress { get; set; } 
        public bool IsEnabled { get; set; }
        public string Description
        {
            get
            {
                string action = Action == AclAction.Permit ? "Permit" : "Deny";
                string protocol = Protocol.ToString();
                string source = "from any address";
                string addressType = "";
                if (SourceAddressType == AddressType.IP)
                {
                    source = SourceIPAddress != null ? $"from {SourceIPAddress}" : "Expecting IP address";
                    addressType = "(IP)";
                }
                else if (SourceAddressType == AddressType.MAC)
                {
                    source = SourceMacAddress != null ? $"from {SourceMacAddress}" : "Expecting MAC address";
                    addressType = "(MAC)";
                }

                string portOrIcmp = "";
                if (Protocol == ProtocolType.TCP || Protocol == ProtocolType.UDP)
                    portOrIcmp = $"on port {PortOfProtocol} ({(int)PortOfProtocol})";
                else if (Protocol == ProtocolType.ICMP && IcmpType.HasValue)
                    portOrIcmp = IcmpType.Value == IcmpMessageType.EchoRequest ? "Echo Request (Deny), Echo Reply (Permit)" : "";

                string direction = Direction == AclDirection.In ? "(In)" : "(Out)";
                return $"{action} {protocol} {source} {addressType} {portOrIcmp} {direction}".Trim();
            }
        }
        public RuleAcl(
            AclAction action,
            AclDirection direction,
            ProtocolType protocol,
            PortOfProtocol? portOfProtocol,
            IcmpMessageType? icmpType,
            AddressType sourceAddressType,
            IPAddress? sourceIPAddress,
            PhysicalAddress? sourceMacAddress,
            AddressType destinationAddressType,
            IPAddress? destinationIPAddress,
            PhysicalAddress? destinationMacAddress,
            bool isEnabled)
        {
            Action = action;
            Direction = direction;
            Protocol = protocol;
            PortOfProtocol = portOfProtocol;
            IcmpType = icmpType;
            SourceAddressType = sourceAddressType;
            SourceIPAddress = sourceIPAddress;
            SourceMacAddress = sourceMacAddress;
            DestinationAddressType = destinationAddressType;
            DestinationIPAddress = destinationIPAddress;
            DestinationMacAddress = destinationMacAddress;
            IsEnabled = isEnabled;
        }
    }
}
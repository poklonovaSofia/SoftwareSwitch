using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SoftSwitch.components
{
    public class ProtocolsCountDictionary
    {
        public Dictionary<string, Dictionary<string, int>> Stats { get; } = new Dictionary<string, Dictionary<string, int>>()
        {
            { "Ethernet", new Dictionary<string, int> { { "in", 0 }, { "out", 0 } } },
            { "ARP", new Dictionary<string, int> { { "in", 0 }, { "out", 0 } } },
            { "IPv4", new Dictionary<string, int> { { "in", 0 }, { "out", 0 } } },
            { "IPv6", new Dictionary<string, int> { { "in", 0 }, { "out", 0 } } },
            { "ICMP", new Dictionary<string, int> { { "in", 0 }, { "out", 0 } } },
            { "TCP", new Dictionary<string, int> { { "in", 0 }, { "out", 0 } } },
            { "UDP", new Dictionary<string, int> { { "in", 0 }, { "out", 0 } } },
            { "HTTP", new Dictionary<string, int> { { "in", 0 }, { "out", 0 } } }
        };
    }
}

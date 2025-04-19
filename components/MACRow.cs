using SharpPcap.WinPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace SoftSwitch.components
{
    public class MACRow
    {
        public PhysicalAddress PhysicalAddress { get; set; }
        public WinPcapDevice Device { get; set; }
        public TimeSpan AgingTime { get; set; }
        public DateTime LastUpdated { get; set; }
        
        public MACRow(PhysicalAddress physicalAddress, WinPcapDevice device, TimeSpan ag)
        {
            PhysicalAddress = physicalAddress ?? throw new ArgumentNullException(nameof(physicalAddress));
            Device = device ?? throw new ArgumentNullException(nameof(device));
            AgingTime = ag > TimeSpan.Zero ? ag : throw new ArgumentException("Aging time must be positive.", nameof(ag));
            LastUpdated = DateTime.Now; 
        }
        public bool IsExpired()
        {
            return (DateTime.Now - LastUpdated) > AgingTime;
        }
        public void UpdateTimestamp()
        {
            LastUpdated = DateTime.Now;
        }
        
    }
}

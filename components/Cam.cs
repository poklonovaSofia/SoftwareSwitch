using PacketDotNet;
using SharpPcap;
using SharpPcap.WinPcap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Mail;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace SoftSwitch.components
{
    public class Cam
    {
        private readonly Dictionary<PhysicalAddress, MACRow> rows = new Dictionary<PhysicalAddress, MACRow>();
        public event Action UpdateMacTableInSwitch;
        public TimeSpan defaultAgingTime = TimeSpan.FromMinutes(1);
        public event Action<PhysicalAddress, WinPcapDevice, WinPcapDevice> OnPortMove;
        public Dictionary<PhysicalAddress, MACRow> getAllRows() 
        {
            var result = new Dictionary<PhysicalAddress, MACRow>();
            foreach (var row in rows)
            {
                if (!row.Value.IsExpired())
                {
                    result[row.Value.PhysicalAddress] = row.Value;
                }
            }
            return result;
        }
        public List<CamTableGUI> GetEntriesForDisplay(Dictionary<WinPcapDevice, string> portNumbers)
        {
            return rows
                .Where(kvp => !kvp.Value.IsExpired()) // Фільтруємо тільки не прострочені записи
                .Select(kvp =>
                {
                    int remainingSeconds = (int)(kvp.Value.AgingTime.TotalSeconds - (DateTime.Now - kvp.Value.LastUpdated).TotalSeconds);
                    return new CamTableGUI
                    {
                        MacAddress = kvp.Key.ToString(),
                        AdapterName = portNumbers.ContainsKey(kvp.Value.Device) ? portNumbers[kvp.Value.Device] : kvp.Value.Device.Description,
                        LifetimeSeconds = Math.Max(0, remainingSeconds) // Запобігаємо від’ємним значенням
                    };
                })
                .ToList();
        }
        public void addRowOrUpdate(PhysicalAddress physicalAddress, WinPcapDevice device)
        {
            if (physicalAddress == null || device == null)
                throw new ArgumentNullException("MAC-адреса або пристрій не можуть бути null.");

            if (rows.TryGetValue(physicalAddress, out MACRow value))
            {
                if(value.Device != device)
                {
                    var oldDevice = value.Device; 
                    value.Device = device; 
                    Debug.WriteLine($"🔄 MAC {physicalAddress} змінив порт з {oldDevice.Description} на {device.Description}");
                    OnPortMove?.Invoke(physicalAddress, oldDevice, device);
                }
                if (value.AgingTime != defaultAgingTime)
                {
                    Debug.WriteLine($"🕒 AgingTime для MAC {physicalAddress} змінено з {value.AgingTime.TotalSeconds} секунд на {defaultAgingTime.TotalSeconds} секунд");
                    value.AgingTime = defaultAgingTime;
                }
                value.UpdateTimestamp();
            }
            else
            {
                rows.Add(physicalAddress, new MACRow(physicalAddress, device, defaultAgingTime));
            }
            UpdateMacTableInSwitch?.Invoke();
        }
        public ICaptureDevice? existMac(PhysicalAddress physicalAddress)
        {
            if(rows.TryGetValue(physicalAddress, out MACRow value))
            {
                return value.Device;
            }
            return null;
        }
        public void monitorExpired()
        {
            var keysToRemove = rows
                .Where(kv => kv.Value.IsExpired())
                .Select(kv => kv.Key)
                .ToList();

            foreach (var key in keysToRemove)
            {
                rows.Remove(key);
                UpdateMacTableInSwitch?.Invoke();
            }
        }
        public void RemoveEntriesForDevice(WinPcapDevice device)
        {
            var keysToRemove = rows
                .Where(kv => kv.Value.Device == device)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var key in keysToRemove)
            {
                rows.Remove(key);
                Debug.WriteLine($"🗑️ Видалено запис з MAC-таблиці для адаптера {device.Name}: {key}");
            }
            UpdateMacTableInSwitch?.Invoke();
        }
        public void clear()
        {
            rows.Clear();
            UpdateMacTableInSwitch?.Invoke();
        }
        public async Task UpdateTtlForDeviceAsync(ICaptureDevice device, int newTtlSeconds)
        {
            await Task.Run(() =>
            {
                foreach (var temp in rows.ToList()) // Створюємо копію, щоб уникнути модифікації під час ітерації
                {
                    var mac = temp.Key;
                    var row = temp.Value;
                    if (row.Device == device)
                    {
                        // Оновлюємо AgingTime для записів, пов’язаних із цим адаптером
                        rows[mac] = new MACRow(row.PhysicalAddress, row.Device, TimeSpan.FromSeconds(newTtlSeconds));
                    }
                }

                Debug.WriteLine($"🕒 TTL оновлено до {newTtlSeconds} секунд для всіх записів адаптера {device.Description}.");
                UpdateMacTableInSwitch?.Invoke(); // Оновлюємо GUI
            });
        }
        public async Task UpdateAllTtlAsync(int newTtlSeconds)
        {
            await Task.Run(() =>
            {
                defaultAgingTime = TimeSpan.FromSeconds(newTtlSeconds);

                // Оновлюємо AgingTime для всіх існуючих записів
                var updatedRows = new Dictionary<PhysicalAddress, MACRow>();
                foreach (var kvp in rows)
                {
                    var row = kvp.Value;
                    updatedRows[kvp.Key] = new MACRow(row.PhysicalAddress, row.Device, defaultAgingTime);
                }
                rows.Clear();
                foreach (var kvp in updatedRows)
                {
                    rows[kvp.Key] = kvp.Value;
                }

                UpdateMacTableInSwitch?.Invoke();
            });
        }
    }
}

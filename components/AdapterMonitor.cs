using SharpPcap;
using SharpPcap.WinPcap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SoftSwitch.components
{
    public class AdapterMonitor
    {
        public event Action<List<WinPcapDevice>> OnAdaptersChanged;
        private List<WinPcapDevice> _lastDevices = new();
        private CancellationTokenSource _cts = new();

        public void StartMonitoring()
        {
            _cts = new CancellationTokenSource();
            Task.Run(() => MonitorAdapters(_cts.Token));
        }

        public void StopMonitoring()
        {
            _cts.Cancel();
        }

        private async Task MonitorAdapters(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    // 1️⃣ Отримуємо список Ethernet-інтерфейсів через NetworkInterface 
                    var ethernetInterfaces = NetworkInterface.GetAllNetworkInterfaces()
                        .Where(ni => Regex.IsMatch(ni.Name, @"^Ethernet") && ni.OperationalStatus == OperationalStatus.Up)
                        .Select(ni => new
                        {
                            Name = ni.Name,
                            MacAddress = ni.GetPhysicalAddress().ToString()
                        })
                        .ToList();

                    /*Debug.WriteLine("📡 Доступні Ethernet-інтерфейси:");
                    foreach (var ni in ethernetInterfaces)
                    {
                        Debug.WriteLine($"🔹 {ni.Name} | MAC: {ni.MacAddress}");
                    }*/

                    // 2️⃣ Отримуємо список пристроїв з SharpPcap
                    var allDevices = WinPcapDeviceList.Instance;
                    var matchedDevices = new List<WinPcapDevice>();

                    foreach (var ethernet in ethernetInterfaces)
                    {
                        //Debug.WriteLine($"🔍 Пошук SharpPcap-пристрою для {ethernet.Name} | MAC: {ethernet.MacAddress}");
                        WinPcapDevice matchingDevice = null;

                        foreach (var device in allDevices)
                        {
                            try
                            {
                                // Відкриваємо пристрій для доступу до MacAddress
                                device.Open(OpenFlags.Promiscuous | OpenFlags.NoCaptureLocal, 1);
                                if (device.MacAddress != null && device.MacAddress.ToString() == ethernet.MacAddress)
                                {
                                    matchingDevice = device;
                                    Debug.WriteLine($"✅ Знайдено збіг: {device.Name} | MAC: {device.MacAddress}");
                                    break; // Знайшли збіг, виходимо з циклу
                                }
                                device.Close(); // Закриваємо, якщо збігу немає
                            }
                            catch (DeviceNotReadyException ex)
                            {
                                Debug.WriteLine($"❌ Пристрій {device.Name} не готовий: {ex.Message}");
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine($"❌ Помилка при роботі з пристроєм {device.Name}: {ex.Message}");
                            }
                        }

                        if (matchingDevice != null)
                        {
                            matchedDevices.Add(matchingDevice);
                            if (matchedDevices.Count == 2) break; // Обмежуємо до 2 адаптерів
                        }
                        else
                        {
                            Debug.WriteLine($"⚠️ Пристрій для {ethernet.Name} не знайдено в SharpPcap.");
                        }
                    }

                   /* // 3️⃣ Логуємо знайдені пристрої
                    Debug.WriteLine("\n🎯 Відповідні SharpPcap-адаптери:");
                    foreach (var adapter in matchedDevices)
                    {
                        Debug.WriteLine("=========================================");
                        Debug.WriteLine($"Description: {adapter.Description}");
                        Debug.WriteLine($"MAC Address: {adapter.MacAddress}");
                        Debug.WriteLine($"Friendly Name: {adapter.Name}");
                    }*/

                    // 4️⃣ Перевіряємо, чи змінився список адаптерів
                    if (!matchedDevices.SequenceEqual(_lastDevices))
                    {
                        _lastDevices = matchedDevices;
                        try
                        {
                            OnAdaptersChanged?.Invoke(matchedDevices);
                            //Debug.WriteLine($"🔄 Список адаптерів оновлено. Кількість: {matchedDevices.Count}");
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"❌ Помилка при виклику OnAdaptersChanged: {ex.Message}");
                        }
                    }
                    else
                    {
                        Debug.WriteLine("ℹ️ Змін у списку адаптерів немає.");
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"❌ Загальна помилка в моніторингу адаптерів: {ex.Message}");
                }

                try
                {
                    await Task.Delay(2000, token);
                }
                catch (TaskCanceledException)
                {
                    Debug.WriteLine("🛑 Моніторинг скасовано.");
                    break;
                }
            }
        }
    }
}
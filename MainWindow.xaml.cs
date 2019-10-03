using ProcessViewer.Interop;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.ComponentModel;
using System.Text;

namespace ProcessViewer
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        public class ProcessInfo
        {
            public uint Pid { get; set; }
            public string Name { get; set; }
            public string MachineType { get; set; }
            public string ImagePath { get; set; }
            public bool IsWow64 { get; set; }
        }

        public ObservableCollection<ProcessInfo> Processes { get; }
            = new ObservableCollection<ProcessInfo>();

        private readonly CollectionViewSource _source;

        public MainWindow()
        {
            InitializeComponent();
            _source = (CollectionViewSource)Resources["Source"];
            _source.Source = Processes;
            _source.SortDescriptions.Add(new SortDescription
            {
                PropertyName = nameof(ProcessInfo.Pid)
            });
        }

        private void RefreshClick(object sender, RoutedEventArgs e)
        {
            Processes.Clear();
            foreach (var ppe in EnumProcesses())
            {
                var (isWow64, machine, imagePath) = QueryProcessInfo(ppe.th32ProcessID);
                Processes.Add(new ProcessInfo
                {
                    Pid = ppe.th32ProcessID,
                    Name = Path.GetFileName(ppe.szExeFile),
                    MachineType = machine.Format(),
                    ImagePath = imagePath,
                    IsWow64 = isWow64,
                });
            }
        }

        private void ListViewHeaderClick(object sender, RoutedEventArgs e)
        {
            if (!(e.OriginalSource is GridViewColumnHeader header)) return;
            var path = ((Binding)header.Column?.DisplayMemberBinding)?.Path?.Path;
            if (path == null) return;
            _source.GroupDescriptions.Clear();
            switch (path)
            {
                case nameof(ProcessInfo.Pid):
                case nameof(ProcessInfo.Name):
                case nameof(ProcessInfo.ImagePath):
                    _source.SortDescriptions.Clear();
                    _source.SortDescriptions.Add(new SortDescription
                    {
                        PropertyName = path,
                    });
                    break;
                default:
                    _source.GroupDescriptions.Add(new PropertyGroupDescription()
                    {
                        PropertyName = path
                    });
                    break;
            }
        }

        private IEnumerable<PROCESSENTRY32> EnumProcesses()
        {
            var snapshot = Kernel32.CreateToolhelp32Snapshot(SnapshotFlags.Process, 0);
            var ppe = new PROCESSENTRY32 { dwSize = Marshal.SizeOf<PROCESSENTRY32>() };
            if (snapshot != IntPtr.Zero && Kernel32.Process32First(snapshot, ref ppe))
            {
                do
                {
                    yield return ppe;
                } while (Kernel32.Process32Next(snapshot, ref ppe));
            }
            Kernel32.CloseHandle(snapshot);
        }

        private (bool isWow64, ImageFileMachine machine, string imagePath) QueryProcessInfo(uint processId)
        {
            using (var process = Process.Open((int)processId, ProcessAccessFlags.QueryLimitedInformation))
            {
                var sb = new StringBuilder(260);
                Psapi.GetModuleFileNameEx(process.Handle, IntPtr.Zero, sb, 260);
                Kernel32.IsWow64Process2(process.Handle, out var processMachine, out var nativeMachine);
                // `processMachine` will be IMAGE_FILE_MACHINE_UNKNOWN if the target process is not a WOW64 process
                var isWow64 = processMachine != ImageFileMachine.Unknown;
                return (isWow64, isWow64 ? processMachine : nativeMachine, sb.ToString());
            }
        }
    }
}

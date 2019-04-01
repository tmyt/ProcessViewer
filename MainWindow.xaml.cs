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

namespace ProcessViewer
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        public class Process
        {
            public uint Pid { get; set; }
            public string Name { get; set; }
            public string MachineType { get; set; }
            public bool IsWow64 { get; set; }
        }

        public ObservableCollection<Process> Processes { get; }
            = new ObservableCollection<Process>();

        private CollectionViewSource _source;

        public MainWindow()
        {
            InitializeComponent();
            _source = (CollectionViewSource)Resources["Source"];
            _source.Source = Processes;
            _source.SortDescriptions.Add(new SortDescription
            {
                PropertyName = nameof(Process.Pid)
            });
        }

        private void RefreshClick(object sender, RoutedEventArgs e)
        {
            Processes.Clear();
            foreach (var ppe in EnumProcesses())
            {
                var isWow64 = QueryMachineType(ppe.th32ProcessID, out var processMachine, out var nativeMachine);
                Processes.Add(new Process
                {
                    Pid = ppe.th32ProcessID,
                    Name = Path.GetFileName(ppe.szExeFile),
                    MachineType = (isWow64 ? nativeMachine : processMachine).Format(),
                    IsWow64 = isWow64,
                });
            }
        }

        private void ListViewHeaderClick(object sender, RoutedEventArgs e)
        {
            if (!(e.OriginalSource is GridViewColumnHeader header)) return;
            var binding = (Binding)header.Column.DisplayMemberBinding;
            switch (binding.Path.Path)
            {
                case nameof(Process.Pid):
                case nameof(Process.Name):
                    _source.GroupDescriptions.Clear();
                    _source.SortDescriptions.Clear();
                    _source.SortDescriptions.Add(new SortDescription()
                    {
                        PropertyName = binding.Path.Path
                    });
                    break;
                default:
                    _source.GroupDescriptions.Clear();
                    _source.GroupDescriptions.Add(new PropertyGroupDescription()
                    {
                        PropertyName = binding.Path.Path
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

        private bool QueryMachineType(uint processId, out ImageFileMachine processMachine, out ImageFileMachine nativeMachine)
        {
            var process = Kernel32.OpenProcess(ProcessAccessFlags.QueryLimitedInformation, false, (int)processId);
            try
            {
                Kernel32.IsWow64Process2(process, out processMachine, out nativeMachine);
                // The value will be IMAGE_FILE_MACHINE_UNKNOWN if the target process is not a WOW64 process
                return processMachine == ImageFileMachine.Unknown;
            }
            finally
            {
                Kernel32.CloseHandle(process);
            }
        }
    }
}

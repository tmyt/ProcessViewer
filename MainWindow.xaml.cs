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

        public ObservableCollection<Process> Processes { get; set; }

        private CollectionViewSource _source;

        public MainWindow()
        {
            InitializeComponent();
            _source = ((CollectionViewSource)Resources["Source"]);
            Processes = new ObservableCollection<Process>();
            _source.Source = Processes;
            _source.SortDescriptions.Add(new SortDescription
            {
                PropertyName = nameof(Process.Name)
            });
        }

        private void RefreshClick(object sender, RoutedEventArgs e)
        {
            foreach (var ppe in EnumProcesses())
            {
                QueryMachineType(ppe.th32ProcessID, out var processMachine, out var nativeMachine);
                Processes.Add(new Process
                {
                    Pid = ppe.th32ProcessID,
                    Name = Path.GetFileName(ppe.szExeFile),
                    MachineType = ((ImageFileMachine)processMachine).Format(),
                    IsWow64 = processMachine != nativeMachine,
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

        private void QueryMachineType(uint processId, out ushort processMachine, out ushort nativeMachine)
        {
            var process = Kernel32.OpenProcess(ProcessAccessFlags.QueryLimitedInformation, false, (int)processId);
            try
            {
                processMachine = 0;
                nativeMachine = 0;
                Kernel32.IsWow64Process2(process, ref processMachine, ref nativeMachine);
                if (processMachine == 0) processMachine = nativeMachine;
            }
            finally
            {
                Kernel32.CloseHandle(process);
            }
        }
    }
}

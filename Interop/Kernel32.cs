using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;

namespace ProcessViewer.Interop
{
    static class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);
        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll")]
        public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32.dll")]
        public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32.dll")]
        public static extern bool IsWow64Process2(IntPtr hProcess, ref ushort pProcessMachine, ref ushort pNativeMachine);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);
    }

    [Flags]
    public enum SnapshotFlags : uint
    {
        HeapList = 0x00000001,
        Process = 0x00000002,
        Thread = 0x00000004,
        Module = 0x00000008,
        Module32 = 0x00000010,
        All = (HeapList | Process | Thread | Module),
        Inherit = 0x80000000,
        NoHeaps = 0x40000000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESSENTRY32
    {
        public int dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    };

    [Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }

    public enum ImageFileMachine
    {
        Unknown = 0, // Unknown
        Host = 0x0001, //Interacts with the host and not a WOW64 guest
        I386 = 0x014c,// Intel 386
        R3000 = 0x0162,//MIPS little-endian, 0x160 big-endian
        R4000 = 0x0166,//MIPS little-endian
        R10000 = 0x0168,//MIPS little-endian
        WCEMIPSV2 = 0x0169,//MIPS little-endian WCE v2
        ALPHA = 0x0184,//Alpha_AXP
        SH3 = 0x01a2,//SH3 little-endian
        SH3DSP = 0x01a3,//SH3DSP
        SH3E = 0x01a4,//SH3E little-endian
        SH4 = 0x01a6,//SH4 little-endian
        SH5 = 0x01a8,//SH5
        ARM = 0x01c0,//ARM Little-Endian
        THUMB = 0x01c2,//ARM Thumb/Thumb-2 Little-Endian
        ARMNT = 0x01c4,//ARM Thumb-2 Little-Endian
        AM33 = 0x01d3,//TAM33BD
        POWERPC = 0x01F0,//IBM PowerPC Little-Endian
        POWERPCFP = 0x01f1,//POWERPCFP
        IA64 = 0x0200,//Intel 64
        MIPS16 = 0x0266,//MIPS
        ALPHA64 = 0x0284,//ALPHA64
        MIPSFPU = 0x0366,//MIPS
        MIPSFPU16 = 0x0466,//MIPS
        //AXP64 = 0x0284,//AXP64
        TRICORE = 0x0520,//Infineon
        CEF = 0x0CEF,//CEF
        EBC = 0x0EBC,//EFI Byte Code
        AMD64 = 0x8664,//AMD64 (K8)
        M32R = 0x9041,//M32R little-endian
        ARM64 = 0xAA64,//ARM64 Little-Endian
        CEE = 0xC0EE,//CEE
    }

    public static class ImageFileMachineEx
    {
        public static string Format(this ImageFileMachine machine)
        {
            switch (machine)
            {
                default:
                case ImageFileMachine.Unknown: return " Unknown";
                case ImageFileMachine.Host: return "Interacts with the host and not a WOW64 guest";
                case ImageFileMachine.I386: return "Intel 386";
                case ImageFileMachine.R3000: return "MIPS little-endian, 0x160 big-endian";
                case ImageFileMachine.R4000: return "MIPS little-endian";
                case ImageFileMachine.R10000: return "MIPS little-endian";
                case ImageFileMachine.WCEMIPSV2: return "MIPS little-endian WCE v2";
                case ImageFileMachine.ALPHA: return "Alpha_AXP";
                case ImageFileMachine.SH3: return "SH3 little-endian";
                case ImageFileMachine.SH3DSP: return "SH3DSP";
                case ImageFileMachine.SH3E: return "SH3E little-endian";
                case ImageFileMachine.SH4: return "SH4 little-endian";
                case ImageFileMachine.SH5: return "SH5";
                case ImageFileMachine.ARM: return "ARM Little-Endian";
                case ImageFileMachine.THUMB: return "ARM Thumb/Thumb-2 Little-Endian";
                case ImageFileMachine.ARMNT: return "ARM Thumb-2 Little-Endian";
                case ImageFileMachine.AM33: return "TAM33BD";
                case ImageFileMachine.POWERPC: return "IBM PowerPC Little-Endian";
                case ImageFileMachine.POWERPCFP: return "POWERPCFP";
                case ImageFileMachine.IA64: return "Intel 64";
                case ImageFileMachine.MIPS16: return "MIPS";
                case ImageFileMachine.ALPHA64: return "ALPHA64 or AXP64";
                case ImageFileMachine.MIPSFPU: return "MIPS";
                case ImageFileMachine.MIPSFPU16: return "MIPS";
                case ImageFileMachine.TRICORE: return "Infineon";
                case ImageFileMachine.CEF: return "CEF";
                case ImageFileMachine.EBC: return "EFI Byte Code";
                case ImageFileMachine.AMD64: return "AMD64 (K8)";
                case ImageFileMachine.M32R: return "M32R little-endian";
                case ImageFileMachine.ARM64: return "ARM64 Little-Endian";
                case ImageFileMachine.CEE: return "CEE";
            }
        }
    }
}

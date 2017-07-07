using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MinInjection {
    public class MinInjectionEntryPoint : EasyHook.IEntryPoint {
        ServerInterface server = null;
        ConcurrentQueue<string> messageQueue = new ConcurrentQueue<string>();
        List<FileSystemPolicy> fileSystemPolicies;
        List<EasyHook.LocalHook> hooks = new List<EasyHook.LocalHook>();

        public MinInjectionEntryPoint(EasyHook.RemoteHooking.IContext context, string channelName) {
            server = EasyHook.RemoteHooking.IpcConnectClient<ServerInterface>(channelName);
            fileSystemPolicies = (from policy in server.policies where policy is FileSystemPolicy select policy)
                .Cast<FileSystemPolicy>()
                .ToList();
            server.Ping();
        }

        void addHook(IntPtr src, Delegate target) {
            var temp = EasyHook.LocalHook.Create(src, target, this);
            temp.ThreadACL.SetExclusiveACL(new Int32[1]);
            hooks.Add(temp);
        }

        public void Run(EasyHook.RemoteHooking.IContext context, string channelName) {
            addHook(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CreateProcessW"),
                new CreateProcess_Delegate(CreateProcess_Hook));
            addHook(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
                new CreateFile_Delegate(CreateFile_Hook));
            addHook(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "OpenFile"),
                new OpenFile_Delegate(OpenFile_Hook));
            addHook(
                EasyHook.LocalHook.GetProcAddress("Shlwapi.dll", "PathFileExistsW"),
                new PathFileExists_Delegate(PathFileExists_Hook));
            addHook(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CreateDirectoryTransactedW"),
                new CreateDirectoryTransacted_Delegate(CreateDirectoryTransacted_Hook));
            addHook(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CreateDirectoryExW"),
                new CreateDirectoryEx_Delegate(CreateDirectoryEx_Hook));
            addHook(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CreateDirectoryW"),
                new CreateDirectory_Delegate(CreateDirectory_Hook));

            var pid = EasyHook.RemoteHooking.GetCurrentProcessId();

            var process = Process.GetCurrentProcess();
            process.Resume();

            try {
                server.Start(pid);
                while (true) {
                    System.Threading.Thread.Sleep(500);
                    server.Ping();
                    var temp = new Queue<string>();
                    while (!messageQueue.IsEmpty && temp.Count < 10) {
                        string str;
                        while (!messageQueue.TryDequeue(out str)) System.Threading.Thread.Sleep(100);
                        temp.Enqueue(str);
                    }
                    if (temp.Count > 0) server.Log(pid, temp.ToArray());
                }
            } catch (Exception e) {
                try {
                    server.Log(pid, e.StackTrace);
                } catch { }
            }

            hooks.ForEach(hook => hook.Dispose());
            EasyHook.LocalHook.Release();
        }

        private void doLog(string content) {
            messageQueue.Enqueue(content);
        }

        private void doLog(Exception content) {
            messageQueue.Enqueue(string.Format("Exception: {0}", content.StackTrace));
        }

        private string getPath(string src) {
            if (src.StartsWith(@"\\?\")) {
                return src.Substring(4);
            } else
                try {
                    return Path.GetFullPath(src);
                } catch {
                    return src;
                }
        }

        #region CreateProcess Hook

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessInfo {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [Flags]
        enum CreateProcessFlags : uint {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool CreateProcess(
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            Boolean bInheritHandles,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            IntPtr lpStartupInfo,
            out ProcessInfo lpProcessInformation
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
                    CharSet = CharSet.Unicode,
                    SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        delegate bool CreateProcess_Delegate(
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            Boolean bInheritHandles,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            IntPtr lpStartupInfo,
            out ProcessInfo lpProcessInformation
        );

        bool CreateProcess_Hook(
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            Boolean bInheritHandles,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            IntPtr lpStartupInfo,
            out ProcessInfo lpProcessInformation
        ) {
            var ret = CreateProcess(
                lpApplicationName,
                lpCommandLine,
                lpProcessAttributes,
                lpThreadAttributes,
                bInheritHandles,
                dwCreationFlags | CreateProcessFlags.CREATE_SUSPENDED,
                lpEnvironment,
                lpCurrentDirectory,
                lpStartupInfo,
                out lpProcessInformation);
            if (ret) {
                var pid = lpProcessInformation.dwProcessId;
                try {
                    server.DoHook(pid);
                    doLog(string.Format("CREATEPROCESS|{0}|{1}|{2}", lpApplicationName, lpCommandLine, pid));
                } catch (Exception e) {
                    doLog(e);
                }
            }
            return ret;
        }

        #endregion

        #region PathFileExists Hook
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
                    CharSet = CharSet.Unicode,
                    SetLastError = true)]
        delegate bool PathFileExists_Delegate(string path);

        [DllImport("Shlwapi.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool PathFileExistsW(string path);

        bool PathFileExists_Hook(string path) {
            try {
                var real = getPath(path);
                if (fileSystemPolicies.Find(policy => {
                    if (policy.action == "pathfileexists") {
                        return policy.fileNameRegex.IsMatch(real);
                    }
                    return false;
                }) != null) {
                    doLog(string.Format("fs|pathfileexists|{0}", real));
                    return true;
                }
            } catch (Exception e) {
                doLog(e.Source);
            }
            return PathFileExistsW(path);
        }
        #endregion

        #region OpenFile Hook

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
                    CharSet = CharSet.Unicode,
                    SetLastError = true)]
        delegate IntPtr OpenFile_Delegate(
            String lpFileName,
            IntPtr lpReOpenBuff,
            uint uStyle);

        [DllImport("kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true,
            CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr OpenFile(
            String lpFileName,
            IntPtr lpReOpenBuff,
            uint uStyle);

        IntPtr OpenFile_Hook(
            String lpFileName,
            IntPtr lpReOpenBuff,
            uint uStyle) {
            try {
                var real = getPath(lpFileName);
                if (fileSystemPolicies.Find(policy => policy.action == "preventcreate" && policy.fileNameRegex.IsMatch(real)) != null) {
                    doLog(string.Format("fs|preventcreate|{0}", real));
                    return new IntPtr(-1);
                }
            } catch (Exception e) {
                doLog(e.Source);
            }
            return OpenFile(lpFileName, lpReOpenBuff, uStyle);
        }

        #endregion

        #region CreateFileW Hook
        [UnmanagedFunctionPointer(CallingConvention.StdCall,
                    CharSet = CharSet.Unicode,
                    SetLastError = true)]
        delegate IntPtr CreateFile_Delegate(
            String filename,
            UInt32 desiredAccess,
            UInt32 shareMode,
            IntPtr securityAttributes,
            UInt32 creationDisposition,
            UInt32 flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true,
            CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr CreateFileW(
            String filename,
            UInt32 desiredAccess,
            UInt32 shareMode,
            IntPtr securityAttributes,
            UInt32 creationDisposition,
            UInt32 flagsAndAttributes,
            IntPtr templateFile);

        IntPtr CreateFile_Hook(
            String filename,
            UInt32 desiredAccess,
            UInt32 shareMode,
            IntPtr securityAttributes,
            UInt32 creationDisposition,
            UInt32 flagsAndAttributes,
            IntPtr templateFile) {
            try {
                var real = getPath(filename);
                if (fileSystemPolicies.Find(policy => policy.action == "preventcreate" && policy.fileNameRegex.IsMatch(real)) != null) {
                    doLog(string.Format("fs|preventcreate|{0}", real));
                    return new IntPtr(-1);
                }
            } catch (Exception e) {
                doLog(e.Source);
            }
            return CreateFileW(
                filename,
                desiredAccess,
                shareMode,
                securityAttributes,
                creationDisposition,
                flagsAndAttributes,
                templateFile);
        }
        #endregion

        #region CreateDirectory Hook
        [DllImport("kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true,
            CallingConvention = CallingConvention.StdCall)]
        static extern bool CreateDirectoryTransactedW(
            string lpTemplateDirectory,
            string lpNewDirectory,
            IntPtr lpSecurityAttributes,
            IntPtr hTransaction);

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
                    CharSet = CharSet.Unicode,
                    SetLastError = true)]
        delegate bool CreateDirectoryTransacted_Delegate(
            string lpTemplateDirectory,
            string lpNewDirectory,
            IntPtr lpSecurityAttributes,
            IntPtr hTransaction);

        bool CreateDirectoryTransacted_Hook(
            string lpTemplateDirectory,
            string lpNewDirectory,
            IntPtr lpSecurityAttributes,
            IntPtr hTransaction) {
            try {
                var real = getPath(lpNewDirectory);
                if (fileSystemPolicies.Find(policy => {
                    if (policy.action == "preventcreate") {
                        return policy.fileNameRegex.IsMatch(real);
                    }
                    return false;
                }) != null) {
                    doLog(string.Format("fs|preventcreate|{0}", real));
                    return false;
                }
            } catch (Exception e) {
                doLog(e.Source);
            }
            return CreateDirectoryTransactedW(lpTemplateDirectory, lpNewDirectory, lpSecurityAttributes, hTransaction);
        }

        [DllImport("kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true,
            CallingConvention = CallingConvention.StdCall)]
        static extern bool CreateDirectoryExW(
            string lpTemplateDirectory,
            string lpNewDirectory,
            IntPtr lpSecurityAttributes);

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
                    CharSet = CharSet.Unicode,
                    SetLastError = true)]
        delegate bool CreateDirectoryEx_Delegate(
            string lpTemplateDirectory,
            string lpNewDirectory,
            IntPtr lpSecurityAttributes);

        bool CreateDirectoryEx_Hook(
            string lpTemplateDirectory,
            string lpNewDirectory,
            IntPtr lpSecurityAttributes) {
            try {
                var real = getPath(lpNewDirectory);
                if (fileSystemPolicies.Find(policy => {
                    if (policy.action == "preventcreate") {
                        return policy.fileNameRegex.IsMatch(real);
                    }
                    return false;
                }) != null) {
                    doLog(string.Format("fs|preventcreate|{0}", real));
                    return false;
                }
            } catch (Exception e) {
                doLog(e.Source);
            }
            return CreateDirectoryExW(lpTemplateDirectory, lpNewDirectory, lpSecurityAttributes);
        }

        [DllImport("kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true,
            CallingConvention = CallingConvention.StdCall)]
        static extern bool CreateDirectoryW(
            string lpNewDirectory,
            IntPtr lpSecurityAttributes);

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
                    CharSet = CharSet.Unicode,
                    SetLastError = true)]
        delegate bool CreateDirectory_Delegate(
            string lpNewDirectory,
            IntPtr lpSecurityAttributes);

        bool CreateDirectory_Hook(
            string lpNewDirectory,
            IntPtr lpSecurityAttributes) {
            try {
                var real = getPath(lpNewDirectory);
                if (fileSystemPolicies.Find(policy => {
                    if (policy.action == "preventcreate") {
                        return policy.fileNameRegex.IsMatch(real);
                    }
                    return false;
                }) != null) {
                    doLog(string.Format("fs|preventcreate|{0}", real));
                    return false;
                }
            } catch (Exception e) {
                doLog(e.Source);
            }
            return CreateDirectoryW(lpNewDirectory, lpSecurityAttributes);
        }

        #endregion
    }
}

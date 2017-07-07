using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using static MinInjection.ProcessExtension;

namespace MinInjectionCtrl {
    class Program {
        static void Main(string[] args) {
            if (args.Length < 2) {
                Console.WriteLine("The number of parameters is too small!");
            }
            if (!File.Exists(args[0])) {
                Console.WriteLine("Failed: Config file not found!");
                return;
            }
            if (!File.Exists(args[1])) {
                Console.WriteLine("Failed: Executable file not found!");
                return;
            }
            string restArg = "";
            restArg = string.Join(" ", args.Skip(1).ToArray());
            if (Environment.GetEnvironmentVariable("DEBUG_MININJECTION") != null) {
                AllocConsole();
            }

            int targetPID;
            string channelName = null;
            string targetCfg = args[0];
            string targetExe = args[1];

            var pids = new ConcurrentDictionary<int, Process>();

            var policies = (from result in
                                from line in File.ReadAllLines(targetCfg)
                                select line.Split(new char[] { '|' }, 3)
                            where result.Length == 3 && result[0] == "fs"
                            select new MinInjection.FileSystemPolicy(result[1], new Regex(result[2]))).Cast<MinInjection.Policy>().ToList();
            string injectionLibrary = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "MinInjection.dll");

            var doInject = new MinInjection.ServerInterface.DoHookFn(pid => EasyHook.RemoteHooking.Inject(
                pid,
                EasyHook.InjectionOptions.DoNotRequireStrongName,
                injectionLibrary,
                injectionLibrary,
                channelName
            ));

            var service = new MinInjection.ServerInterface(
                policies,
                doInject,
                pid => {
                    MinInjection.ServerInterface.printPrefix(pid);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Attached");
                    Console.ResetColor();
                    var proc = Process.GetProcessById(pid);
                    proc.EnableRaisingEvents = true;
                    proc.Exited += (s, e) => {
                        MinInjection.ServerInterface.printPrefix(pid);
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Deattached");
                        Console.ResetColor();
                        while (!pids.TryRemove(pid, out proc)) System.Threading.Thread.Sleep(5);
                    };
                    while (!pids.TryAdd(pid, proc)) System.Threading.Thread.Sleep(5);
                }
            );

            EasyHook.RemoteHooking.IpcCreateServer(ref channelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton, service);
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            CreateProcess(targetExe, restArg, IntPtr.Zero, IntPtr.Zero, false, 0x00000016, IntPtr.Zero, null, ref si, out pi);
            targetPID = pi.dwProcessId;
            if (targetPID == 0) {
                return;
            }
            if (!DebugActiveProcessStop(targetPID)) Thread.Sleep(10);
            doInject(targetPID);
            while (pids.IsEmpty) Thread.Sleep(15);
            while (!pids.IsEmpty) Thread.Sleep(10);
        }

        [DllImport("Kernel32.dll", SetLastError = true)]
        static extern bool DebugActiveProcessStop(int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern bool AllocConsole();
    }
}

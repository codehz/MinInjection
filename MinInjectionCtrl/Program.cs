using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

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
            if (args.Length > 2)
                restArg = string.Join(" ", args.Skip(2).ToArray());

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
            var service = new MinInjection.ServerInterface(
                policies,
                pid => EasyHook.RemoteHooking.Inject(
                    pid,
                    EasyHook.InjectionOptions.DoNotRequireStrongName,
                    injectionLibrary,
                    injectionLibrary,
                    channelName
                ),
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
            EasyHook.RemoteHooking.CreateAndInject(
                    targetExe,          // executable to run
                    restArg,            // command line arguments for target
                    0x00000010,         // additional process creation flags to pass to CreateProcess
                    EasyHook.InjectionOptions.DoNotRequireStrongName, // allow injectionLibrary to be unsigned
                    injectionLibrary,   // 32-bit library to inject (if target is 32-bit)
                    injectionLibrary,   // 64-bit library to inject (if target is 64-bit)
                    out targetPID,      // retrieve the newly created process ID
                    channelName         // the parameters to pass into injected library
                );
            while (pids.IsEmpty) System.Threading.Thread.Sleep(15);
            while (!pids.IsEmpty) System.Threading.Thread.Sleep(10);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MinInjection {
    public class ServerInterface : MarshalByRefObject {
        public delegate void DoHookFn(int pid);
        public delegate void Attached(int pid);

        public ServerInterface(List<Policy> list, DoHookFn fn, Attached fn2) {
            policies = list;
            doHook = fn;
            attached = fn2;
        }
        private readonly DoHookFn doHook;
        private readonly Attached attached;
        public readonly List<Policy> policies;
        public void DoHook(int pid) {
            doHook(pid);
        }
        public static void printPrefix(int pid) {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write("[{0:u}]", DateTime.Now);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("{0:X08} ", pid);
            Console.ResetColor();
        }
        public void Log(int pid, string[] contents) {
            printPrefix(pid);
            Console.WriteLine("Say:");
            Array.ForEach(contents, content => Console.WriteLine("\t{0}", content));
        }
        public void Log(int pid, string content) {
            printPrefix(pid);
            Console.WriteLine("Say: {0}", content);
        }
        public void Start(int pid) {
            attached(pid);
        }
        public void Ping() {

        }
    }
}

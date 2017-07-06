using System.Text.RegularExpressions;

namespace MinInjection {
    public class FileSystemPolicy : Policy {
        public FileSystemPolicy(string action, Regex re) {
            this.action = action;
            fileNameRegex = re;
        }
        public string action;
        public Regex fileNameRegex;
    }
}

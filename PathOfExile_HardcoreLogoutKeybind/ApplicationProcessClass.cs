using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;
using System.Windows;
using System.Windows.Forms;
using PathOfExile_HardcoreLogoutKeybind.Properties;


namespace PathOfExile_HardcoreLogoutKeybind
{
    class ApplicationProcessClass
    {
        // shared with utility classes
        public static IntPtr poe_hWnd;
        public static uint mPoePid;

        // internal
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private static LowLevelKeyboardProc _proc = HookCallback;
        private static IntPtr _hookID = IntPtr.Zero;
        private static Int32 KEYCODE_CFG = 192;
        private static Int32 KEYCODE_HIDEOUT = 116;
        private static Int32 KEYCODE_WHOIS = 115;
        private static Int32 KEYCODE_REMAIN = 114;

        #region DLL_Imports
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
        #endregion


        /// <summary>
        /// Application's primary thread (MAIN)
        /// </summary>
        /// <param name="args">no args required</param>
        [STAThread]
        static void Main(string[] args)
        {
            String keycode = System.Configuration.ConfigurationManager.AppSettings["kill_key"];
            KEYCODE_CFG = Int32.Parse(keycode);

            if (Win32Util.CheckIsElevatedPrincipal())
            { // admin required for TCP/IP manipulation (but not keyboard logging?)
            }
            else
            {
                // feed error
                LogToConsole("Privilege Check failed -- run as Administrator.", 2);
                MessageBox.Show("PathOfExile.exe killer must be run as Administrator.", "Incorrect Permissions", MessageBoxButtons.OK, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1);
                System.Environment.Exit(0);
            }

            setupPoePid();

            try
            {
                _hookID = SetHook(_proc);
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                Application.Run(new MyCustomApplicationContext());
            }
            finally
            {
                UnhookWindowsHookEx(_hookID);
                Application.Exit();
            }
        }



        public static void setupPoePid()
        {
            bool runOnce = true;
            // Run every 100ms and attempt to find game client
            while (true)
            {
                // Get process handler from name
                foreach (Process proc in Process.GetProcesses())
                {
                    if (proc.MainWindowTitle.Equals(@"Path of Exile"))
                    {
                        poe_hWnd = proc.MainWindowHandle;
                        break;
                    }
                }

                LogToConsole("Waiting for PoE process...", 0);

                // If PoE is not running
                if (poe_hWnd == IntPtr.Zero)
                {
                    // If first run print text
                    if (runOnce)
                    {
                        runOnce = false;
                        LogToConsole("First try for PoE process failed ...", 1);
                    }

                    // this MessageBox will block the main thread until 'Path Of Exile' is found
                    DialogResult resultA = MessageBox.Show("PathOfExile.exe process window was not found.\r\n\r\nPlease start Path of Exile and press OK.\r\n", "Path of Exile Not Found", MessageBoxButtons.RetryCancel, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1);

                    if (resultA == DialogResult.Cancel)
                    {
                        // if the user clicked 'Cancel' we just abort and GTFO
                        System.Environment.Exit(0);
                    }

                    // the user clicked 'Retry' lets loop and look for the PID again
                    continue;
                }

                // Get window PID from handler
                Win32Util.GetWindowThreadProcessId(poe_hWnd, out mPoePid);
                // Not 100% sure if needed but I'll keep it here just to be safe
                if (mPoePid <= 0) continue;
                break;
            }
        }


        /// <summary>
        /// Sets the hook on the current process. required to get keyboard events at a low level
        /// </summary>
        /// <param name="proc"></param>
        /// <returns></returns>
        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                    GetModuleHandle(curModule.ModuleName), 0);
            }
        }

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        /// <summary>
        /// This hook is called for each keyboard press
        /// </summary>
        /// <param name="nCode"></param>
        /// <param name="wParam"></param>
        /// <param name="lParam"></param>
        /// <returns></returns>
        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
            {
                int vkCode = Marshal.ReadInt32(lParam);
                if (vkCode == KEYCODE_CFG)
                {
                    if (Win32Util.CheckIsPOEForeground())
                    { // don't do it if alt-tabbed (maybe you typed the tilde somewhere  else)
                        LogToConsole("Closing TCP connections...", 0);
                        long delay = TCPUtil.TerminateConnection(mPoePid);
                        LogToConsole("Closed connections (took " + delay + " ms)", 0);
                    }
                    else
                    {
                        // feed error
                        LogToConsole("Path of Exile handle not found.", 2);
                    }
                }
                else if (vkCode == KEYCODE_HIDEOUT)
                {
                    POEUtil.GoToHideout();
                }
                else if (vkCode == KEYCODE_WHOIS)
                {
                    POEUtil.WhoisStem();
                }
                else if (vkCode == KEYCODE_REMAIN)
                {
                    POEUtil.RemainingCommand();
                }
                LogToConsole("KEY: " + (Keys)vkCode, -1);
            }

            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }

        /// <summary>
        /// Print a log message
        /// </summary>
        /// <param name="str">The Log</param>
        /// <param name="status">Log Level (-1 to 3)</param>
        /// <returns></returns>
        public static void LogToConsole(string str, int status)
        {
            string prefix;

            switch (status)
            {
                default:
                case -1:
                    prefix = "[DEBUG] ";
                    return;
                //break;
                case 0:
                    prefix = "[INFO] ";
                    break;
                case 1:
                    prefix = "[WARN] ";
                    break;
                case 2:
                    prefix = "[ERROR] ";
                    break;
                case 3:
                    prefix = "[CRITICAL] ";
                    break;
            }

            string time = string.Format("{0:HH:mm:ss}", DateTime.Now);
            Console.WriteLine("[" + time + "]" + prefix + str);

        }
    }

    public sealed class Win32Util
    {
        #region DLL_Imports
        [DllImport("user32.dll", SetLastError = true)]
        static public extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetWindowRect(IntPtr hWnd, ref WinPos lpRect);
        #endregion

        // structs
        [StructLayout(LayoutKind.Sequential)]
        public struct WinPos
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        /// <summary>
        /// Checks to make sure PoE is the top window.
        /// </summary>
        /// <returns>True if PoE is top window, false if not.</returns>
        public static bool CheckIsPOEForeground()
        {
            StringBuilder Buff = new StringBuilder(256);
            IntPtr handle = GetForegroundWindow();

            if (GetWindowText(handle, Buff, 256) > 0)
            {
                // NOTE: this seems to alwys be the name of the executable no matter what I change the options to
                if (Buff.ToString().Equals("Path of Exile"))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Checks to see if we have admin
        /// </summary>
        /// <returns>True if we are ADMIN, false if not.</returns>
        public static bool CheckIsElevatedPrincipal()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }

    public sealed class TCPUtil
    {
        #region DLL_Imports
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TcpTableClass tblClass, uint reserved = 0);

        [DllImport("iphlpapi.dll")]
        private static extern int SetTcpEntry(IntPtr pTcprow);

        // structs
        [StructLayout(LayoutKind.Sequential)]
        public struct MibTcprowOwnerPid
        {
            public uint state;
            public uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] localPort;
            public uint remoteAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] remotePort;
            public uint owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MibTcptableOwnerPid
        {
            public uint dwNumEntries;
            private readonly MibTcprowOwnerPid table;
        }

        // enums
        private enum TcpTableClass
        {
            TcpTableBasicListener,
            TcpTableBasicConnections,
            TcpTableBasicAll,
            TcpTableOwnerPidListener,
            TcpTableOwnerPidConnections,
            TcpTableOwnerPidAll,
            TcpTableOwnerModuleListener,
            TcpTableOwnerModuleConnections,
            TcpTableOwnerModuleAll
        }
        #endregion

        /// <summary>
        /// Murders the connections of a process 
        /// </summary>
        /// <param name="processId">The PID of the process to operate on</param>
        /// <returns>The number of MS it look to commit </returns>
        public static long TerminateConnection(uint processId)
        {
            long startTime = DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond;


            // NOTE:
            // this code comes from 
            // https://github.com/jkells/socket-free/blob/master/src/IphlapiWrapper.cs
            //
            // this code frees up sockets for t his process

            MibTcprowOwnerPid[] table;
            var afInet = 2;
            var buffSize = 0;
            var ret = GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, afInet, TcpTableClass.TcpTableOwnerPidAll);
            var buffTable = Marshal.AllocHGlobal(buffSize);

            try
            {
                uint statusCode = GetExtendedTcpTable(buffTable, ref buffSize, true, afInet, TcpTableClass.TcpTableOwnerPidAll);
                if (statusCode != 0) return -1;

                var tab = (MibTcptableOwnerPid)Marshal.PtrToStructure(buffTable, typeof(MibTcptableOwnerPid));
                var rowPtr = (IntPtr)((long)buffTable + Marshal.SizeOf(tab.dwNumEntries));
                table = new MibTcprowOwnerPid[tab.dwNumEntries];

                for (var i = 0; i < tab.dwNumEntries; i++)
                {
                    var tcpRow = (MibTcprowOwnerPid)Marshal.PtrToStructure(rowPtr, typeof(MibTcprowOwnerPid));
                    table[i] = tcpRow;
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(tcpRow));
                }

            }
            finally
            {
                Marshal.FreeHGlobal(buffTable);
            }


            // NOTE:
            // this code comes from
            // https://stackoverflow.com/questions/1672062/how-to-close-a-tcp-connection-by-port
            //
            // here we set the TcpEntry state to 12 (Delete_TCB)
            var PathConnection = table.FirstOrDefault(t => t.owningPid == processId);
            PathConnection.state = 12;
            var ptr = Marshal.AllocCoTaskMem(Marshal.SizeOf(PathConnection));
            Marshal.StructureToPtr(PathConnection, ptr, false);
            SetTcpEntry(ptr);

            return DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond - startTime;
        }

    }

    public sealed class POEUtil
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        public static extern IntPtr PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        public static void RemainingCommand()
        {
            IntPtr WindowName = FindWindow(null, "Path of Exile");

            PostMessage(WindowName, 0x100, (IntPtr)Keys.Enter, IntPtr.Zero);
            System.Threading.Thread.Sleep(5);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.OemQuestion, IntPtr.Zero);
            System.Threading.Thread.Sleep(6);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.R, IntPtr.Zero);
            System.Threading.Thread.Sleep(5);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.E, IntPtr.Zero);
            System.Threading.Thread.Sleep(8);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.M, IntPtr.Zero);
            System.Threading.Thread.Sleep(4);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.A, IntPtr.Zero);
            System.Threading.Thread.Sleep(7);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.I, IntPtr.Zero);
            System.Threading.Thread.Sleep(9);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.N, IntPtr.Zero);
            System.Threading.Thread.Sleep(10);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.I, IntPtr.Zero);
            System.Threading.Thread.Sleep(10);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.N, IntPtr.Zero);
            System.Threading.Thread.Sleep(10);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.G, IntPtr.Zero);
            System.Threading.Thread.Sleep(10);
            PostMessage(WindowName, 0x100, (IntPtr)Keys.Enter, IntPtr.Zero);
            System.Threading.Thread.Sleep(10);
        }

        public static void WhoisStem()
        {
            IntPtr WindowName = FindWindow(null, "Path of Exile");

            PostMessage(WindowName, 0x100, (IntPtr)Keys.Enter, IntPtr.Zero);
            System.Threading.Thread.Sleep(5);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.OemQuestion, IntPtr.Zero);
            System.Threading.Thread.Sleep(6);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.W, IntPtr.Zero);
            System.Threading.Thread.Sleep(5);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.H, IntPtr.Zero);
            System.Threading.Thread.Sleep(8);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.O, IntPtr.Zero);
            System.Threading.Thread.Sleep(4);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.I, IntPtr.Zero);
            System.Threading.Thread.Sleep(7);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.S, IntPtr.Zero);
            System.Threading.Thread.Sleep(9);
            PostMessage(WindowName, 0x100, (IntPtr)Keys.Space, IntPtr.Zero);
            System.Threading.Thread.Sleep(10);
        }


        public static void GoToHideout()
        {
            IntPtr WindowName = FindWindow(null, "Path of Exile");

            PostMessage(WindowName, 0x100, (IntPtr)Keys.Enter, IntPtr.Zero);
            System.Threading.Thread.Sleep(5);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.OemQuestion, IntPtr.Zero);
            System.Threading.Thread.Sleep(6);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.H, IntPtr.Zero);
            System.Threading.Thread.Sleep(5);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.I, IntPtr.Zero);
            System.Threading.Thread.Sleep(8);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.D, IntPtr.Zero);
            System.Threading.Thread.Sleep(4);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.E, IntPtr.Zero);
            System.Threading.Thread.Sleep(7);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.O, IntPtr.Zero);
            System.Threading.Thread.Sleep(9);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.U, IntPtr.Zero);
            System.Threading.Thread.Sleep(10);
            PostMessage(WindowName, 0x101, (IntPtr)Keys.T, IntPtr.Zero);
            System.Threading.Thread.Sleep(10);
            PostMessage(WindowName, 0x100, (IntPtr)Keys.Enter, IntPtr.Zero);
            System.Threading.Thread.Sleep(10);
        }
    }

    public class MyCustomApplicationContext : ApplicationContext
    {
        private NotifyIcon trayIcon;

        public MyCustomApplicationContext()
        {
            // Initialize Tray Icon
            trayIcon = new NotifyIcon()
            {
                Icon = Resources.AppIcon,
                Text = "PoE Hardcore Logout",
                ContextMenu = new ContextMenu(new MenuItem[] {
                new MenuItem("Refresh", Refresh),
                new MenuItem("Exit", Exit)
            }),
                Visible = true
            };
        }

        void Exit(object sender, EventArgs e)
        {
            // Hide tray icon, otherwise it will remain shown until user mouses over it
            trayIcon.Visible = false;

            Application.Exit();
        }

        void Refresh(object sender, EventArgs e)
        {
            ApplicationProcessClass.setupPoePid();
        }
    }
}
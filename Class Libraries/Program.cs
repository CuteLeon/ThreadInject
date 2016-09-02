using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
namespace Injection {
    static class Program {
        //线程是否结束
        static bool IsEnd = false;

        /// <summary>
        /// 应用程序的主入口点。
        /// </summary>
        [STAThread]
        static void Main(string[] args) {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            //Application.Run(new Form1());

            Injection MyInjection = new Injection();
#if DEBUG //仅在Debug模式编译
            #region 打开控制台调试
            MyInjection.ShowConsole();
            MyInjection.EnableQuickEditMode();
            Console.WriteLine("\n线程注入测试开始！\n");
            #endregion
#endif
            #region 打开Debug权限
            bool debug = MyInjection.EnablePrivilege(Privilege.SE_DEBUG_NAME, true);
            if (!debug) {
                Console.WriteLine("打开Debug权限失败。\n");
            } else {
                Console.WriteLine("打开Debug权限成功。\n");
            }
            #endregion

            #region 智能加载32/64位DLL
            string DllPath, PName;
            if (Environment.Is64BitProcess) {
                Console.WriteLine("即将使用64位组件。\n");
                Console.WriteLine("注入目标为计算器（calc.exe）。\n");
                PName = "calc";
                DllPath = Application.StartupPath + "\\Win64Test.dll";
            } else {
                Console.WriteLine("即将使用32位组件。\n");
                Console.WriteLine("注入目标为EditPlus（editplus.exe）。\n");
                PName = "editplus";
                DllPath = Application.StartupPath + "\\Win32Test.dll";
            }
            #endregion

            #region 提示打开目标程序
            Console.WriteLine("请确保上述进程已运行，按任意键继续...！\n");
#if DEBUG 
            Console.ReadKey(true); 
#endif
            #endregion

            #region 取得进程PID
            Process[] localByName = Process.GetProcessesByName(PName);
            if (localByName.Length == 0) {
                Console.WriteLine("未发现宿主进程！\n");
#if DEBUG 
            Console.ReadKey(true); 
#endif
                return;
            }
            #endregion

            #region 注入线程
            IntPtr Remote = MyInjection.RemoteThread(localByName[0].Id, DllPath, tState.Active, MyCallBack);
            if (Remote == IntPtr.Zero) {
                Console.WriteLine("注入线程失败！\n");
#if DEBUG 
            Console.ReadKey(true); 
#endif
                return;
            } else {
                Console.WriteLine(string.Format("注入线程成功[{0}]，按任意键继续...！\n", Remote));
#if DEBUG 
            Console.ReadKey(true); 
#endif
            }
            #endregion

            #region 挂起线程
            bool Suspend = MyInjection.SuspendThread();
            if (!Suspend) {
                Console.WriteLine("挂起线程失败！\n");
            } else {
                Console.WriteLine("挂起线程成功，按任意键继续...！\n");
#if DEBUG 
            Console.ReadKey(true); 
#endif
            }
            #endregion

            #region 恢复线程
            bool Resume = MyInjection.ResumeThread();
            if (!Resume) {
                Console.WriteLine("恢复线程失败！\n");
            } else {
                Console.WriteLine("恢复线程成功，按任意键继续...！\n");
#if DEBUG 
            Console.ReadKey(true); 
#endif
            }
            #endregion

            #region 等待回调函数设置全局变量
            while (!IsEnd) {
                Console.WriteLine("请先关闭注入线程的弹出窗口...！\n");
#if DEBUG 
            Console.ReadKey(true); 
#endif
            }
            #endregion

            #region 测试完毕
            Console.WriteLine("线程注入测试完毕，按任意键退出！\n");
#if DEBUG 
            Console.ReadKey(true); 
#endif
            #endregion

        }

        /// <summary>
        /// 线程结束回调函数
        /// </summary>
        /// <param name="State">是否清理资源</param>
        private static void MyCallBack(bool State) {
            IsEnd = true;
            Console.WriteLine(string.Format("- 回调函数返回信息 ---------------------------\n-", State));
            Console.WriteLine(string.Format("- 线程运行结束，清理资源{0}。\n-", State ? "成功" : "失败"));
            Console.WriteLine(string.Format("----------------------------------------------\n", State));
        }
    }
}

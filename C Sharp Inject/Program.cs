using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using System.Diagnostics;
using DeadFish.Threading;

namespace CSharpInject {
    static class Program {
        /// <summary>
        /// 应用程序的主入口点。
        /// </summary>
        [STAThread]
        static void Main() {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            //获取资源管理器的进程ID
            Process[] Desc = Process.GetProcessesByName("explorer");
            if (Desc.Length == 0) return;
            int pid = Desc[0].Id;

            //实例化一个线程注入类
            Injection MyInjection = new Injection();

            //提升到Debug权限
            bool IsOk = MyInjection.EnablePrivilege(Privilege.SE_DEBUG_NAME, true);

            //注入一个线程
            IntPtr tHandle = MyInjection.RemoteThread(pid, @"G:\Soft Develop\Thread Injection\Release\Win64Test.dll", tState.Active, MyCall);

            //注入失败（请不要尝试用32位软件注入64位软件）
            if (tHandle == IntPtr.Zero) MessageBox.Show("注入失败。", "线程注入测试", MessageBoxButtons.OK, MessageBoxIcon.Information);

            //挂起注入的线程
            bool Suspend = MyInjection.SuspendThread();

            //恢复注入的线程
            bool Resume = MyInjection.ResumeThread();

        }

        //回调函数不要处理大量数据，因为超时会被清理
        private static void MyCall(bool State) {
            //新建线程，处理事务
            Thread MsgThread = new Thread(Msgbox);
            MsgThread.Start(State);
        }

        //返回线程资源清理结果
        private static void Msgbox(object State) {
            MessageBox.Show(string.Format("线程结束，资源清理{0}。", (bool)State ? "成功" : "失败"), "线程注入测试", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

    }
}

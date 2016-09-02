using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DeadFish {
    namespace Threading {


        #region 线程注入相关枚举
        public enum tState {
            Active = 0x0,//立即运行线程
            Suspended = 0x4//等待调用ResumeThread
        }
        #endregion

        #region 打开进程权限的相关枚举
        public enum Privilege {
            SE_CREATE_TOKEN_NAME,
            SE_ASSIGNPRIMARYTOKEN_NAME,
            SE_LOCK_MEMORY_NAME,
            SE_INCREASE_QUOTA_NAME,
            SE_UNSOLICITED_INPUT_NAME,
            SE_MACHINE_ACCOUNT_NAME,
            SE_TCB_NAME,
            SE_SECURITY_NAME,
            SE_TAKE_OWNERSHIP_NAME,
            SE_LOAD_DRIVER_NAME,
            SE_SYSTEM_PROFILE_NAME,
            SE_SYSTEMTIME_NAME,
            SE_PROF_SINGLE_PROCESS_NAME,
            SE_INC_BASE_PRIORITY_NAME,
            SE_CREATE_PAGEFILE_NAME,
            SE_CREATE_PERMANENT_NAME,
            SE_BACKUP_NAME,
            SE_RESTORE_NAME,
            SE_SHUTDOWN_NAME,
            SE_DEBUG_NAME,
            SE_AUDIT_NAME,
            SE_SYSTEM_ENVIRONMENT_NAME,
            SE_CHANGE_NOTIFY_NAME,
            SE_REMOTE_SHUTDOWN_NAME,
            SE_UNDOCK_NAME,
            SE_SYNC_AGENT_NAME,
            SE_ENABLE_DELEGATION_NAME,
            SE_MANAGE_VOLUME_NAME,
        }
        #endregion

        public class Injection {
            #region 打开进程权限的相关常量
            private const int TOKEN_QUERY = 0x8;
            private const int TOKEN_ADJUST_PRIVILEGES = 0x20;
            private const int ANYSIZE_ARRAY = 1;
            private const int SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
            private const int SE_PRIVILEGE_ENABLED = 0x2;
            #endregion

            #region 打开进程权限的相关结构体
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
            private struct LARGE_INTEGER {
                public int LowPart;
                public int HighPart;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
            private struct LUID_AND_ATTRIBUTES {
                public LARGE_INTEGER pLuid;
                public int Attributes;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
            private struct TOKEN_PRIVILEGES {
                public int PrivilegeCount;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = ANYSIZE_ARRAY)]
                public LUID_AND_ATTRIBUTES[] Privileges;
            }
            #endregion

            #region 打开进程权限的相关函数声明
            [DllImport("kernel32.dll")]
            private static extern IntPtr GetCurrentProcess();
            [DllImport("advapi32.dll")]
            private static extern int OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);
            [DllImport("advapi32.dll")]
            private static extern int LookupPrivilegeValue(string lpSystemName, string lpName, ref LARGE_INTEGER lpLuid);
            [DllImport("advapi32.dll")]
            private static extern int AdjustTokenPrivileges(IntPtr TokenHandle, int DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, ref TOKEN_PRIVILEGES PreviousState, ref int ReturnLength);
            [DllImport("kernel32")]
            private static extern int CloseHandle(IntPtr hObject);
            #endregion

            #region 线程注入相关的函数声明
            [DllImport("kernel32.dll")]
            private static extern IntPtr VirtualAllocEx(IntPtr hwnd, int lpaddress, int size, int type, int tect);

            [DllImport("kernel32.dll")]
            private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, int dwFreeType);

            [DllImport("kernel32.dll")]
            private static extern int WriteProcessMemory(IntPtr hwnd, IntPtr baseaddress, string buffer, int nsize, int filewriten);
            [DllImport("kernel32.dll")]
            private static extern IntPtr GetProcAddress(IntPtr hwnd, string lpname);
            [DllImport("kernel32.dll")]
            private static extern IntPtr GetModuleHandle(string name);
            [DllImport("kernel32.dll")]
            private static extern IntPtr CreateRemoteThread(IntPtr hThread, int attrib, int size, IntPtr address, IntPtr par, tState flags, int threadid);
            [DllImport("kernel32.dll")]

            private static extern int ResumeThread(IntPtr hThread);
            [DllImport("kernel32.dll")]
            private static extern int SuspendThread(IntPtr hThread);
            [DllImport("kernel32.dll")]
            private static extern int TerminateThread(IntPtr hThread, IntPtr dwExitCode);
            [DllImport("kernel32.dll")]
            private static extern int WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);
            [DllImport("kernel32.dll")]
            private static extern int GetExitCodeThread(IntPtr hThread, out IntPtr lpExitCode);
            #endregion

            #region 线程注入相关枚举
            private enum hState {
                WAIT_ABANDONED = 0x00000080,
                WAIT_OBJECT_0 = 0x00000000,
                WAIT_TIMEOUT = 0x00000102,
                WAIT_FAILED = -1 //(uint)0xFFFFFFFF
            }
            #endregion

            #region 其他的一些函数声明
            [DllImport("kernel32.dll")]
            private static extern int GetLastError();
            #endregion

            #region 构造函数
            //狗日的不能枚举字符串
            private string[] SE_NAME = new string[0x1C];
            public Injection() {
                SE_NAME[0x00] = "SeCreateTokenPrivilege";
                SE_NAME[0x01] = "SeAssignPrimaryTokenPrivilege";
                SE_NAME[0x02] = "SeLockMemoryPrivilege";
                SE_NAME[0x03] = "SeIncreaseQuotaPrivilege";
                SE_NAME[0x04] = "SeUnsolicitedInputPrivilege";
                SE_NAME[0x05] = "SeMachineAccountPrivilege";
                SE_NAME[0x06] = "SeTcbPrivilege";
                SE_NAME[0x07] = "SeSecurityPrivilege";
                SE_NAME[0x08] = "SeTakeOwnershipPrivilege";
                SE_NAME[0x09] = "SeLoadDriverPrivilege";
                SE_NAME[0x0A] = "SeSystemProfilePrivilege";
                SE_NAME[0x0B] = "SeSystemtimePrivilege";
                SE_NAME[0x0C] = "SeProfileSingleProcessPrivilege";
                SE_NAME[0x0D] = "SeIncreaseBasePriorityPrivilege";
                SE_NAME[0x0E] = "SeCreatePagefilePrivilege";
                SE_NAME[0x0F] = "SeCreatePermanentPrivilege";
                SE_NAME[0x10] = "SeBackupPrivilege";
                SE_NAME[0x11] = "SeRestorePrivilege";
                SE_NAME[0x12] = "SeShutdownPrivilege";
                SE_NAME[0x13] = "SeDebugPrivilege";
                SE_NAME[0x14] = "SeAuditPrivilege";
                SE_NAME[0x15] = "SeSystemEnvironmentPrivilege";
                SE_NAME[0x16] = "SeChangeNotifyPrivilege";
                SE_NAME[0x17] = "SeRemoteShutdownPrivilege";
                SE_NAME[0x18] = "SeUndockPrivilege";
                SE_NAME[0x19] = "SeSyncAgentPrivilege";
                SE_NAME[0x1A] = "SeEnableDelegationPrivilege";
                SE_NAME[0x1B] = "SeManageVolumePrivilege";
            }
            #endregion

            #region 保存注入线程相关信息的变量
            //记录申请的内存地址
            private IntPtr Memory;

            //记录注入线程的句柄
            private IntPtr hThread;

            //记录注入的进程
            private IntPtr hProcess;

            //进程PID
            private int ProcessPid;

            //注入文件名
            private string fFullName;
            #endregion


            public delegate void CallBack(bool State);
            private static CallBack UserFun;

            /// <summary>
            /// 打开或还原进程权限
            /// </summary>
            /// <param name="Access">系统特权枚举</param>
            /// <param name="Enable">表打开或还原默认</param>
            /// <returns>返回一个布尔型，表示成功和失败</returns>
            public bool EnablePrivilege(Privilege Access, bool Enable) {
                IntPtr hToken = new IntPtr();

                //获取当前进程虚拟句柄
                IntPtr DescProcess = GetCurrentProcess();

                //打开进程令牌
                int htRet = OpenProcessToken(DescProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref hToken);
                if (hToken == null) return false;

                //获取系统特权值
                LARGE_INTEGER SeDebug = new LARGE_INTEGER();
                int LookRet = LookupPrivilegeValue(null, SE_NAME[(int)Access], ref SeDebug);
                if (LookRet == 0) goto Close;

                //构造DeBug特权令牌
                TOKEN_PRIVILEGES nToken = new TOKEN_PRIVILEGES();
                LUID_AND_ATTRIBUTES nAttrib = new LUID_AND_ATTRIBUTES();
                nAttrib.pLuid = SeDebug;
                nAttrib.Attributes = Enable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_ENABLED_BY_DEFAULT;
                nToken.PrivilegeCount = 1;
                nToken.Privileges = new LUID_AND_ATTRIBUTES[] { nAttrib };
                int nSize = System.Runtime.InteropServices.Marshal.SizeOf(nToken);

                //接受原始令牌信息
                TOKEN_PRIVILEGES rToken = new TOKEN_PRIVILEGES();
                int rSize = 0;

                //打开进程权限[注意：该API返回值不表示成功与失败]
                int Temp = AdjustTokenPrivileges(hToken, 0, ref nToken, nSize, ref rToken, ref rSize);
                int Result = GetLastError();

                //打开/关闭特权失败
                if (Result != 0) goto Close;

                //打开/关闭特权成功
                return true;

            Close:
                CloseHandle(hToken);
                return false;
            }

            /// <summary>
            /// 注入远程线程
            /// </summary>
            /// <param name="DescProcess">进程句柄</param>
            /// <param name="DllPath">DLL文件路径</param>
            /// <param name="flags">运行状态</param>
            /// <param name="UserFun">指定回调函数，该函数应无返回并值接受一个bool型参数</param>
            /// <returns>返回一个布尔型，表示成功和失败</returns>
            public IntPtr RemoteThread(int DescProcess, string DllPath, tState flags, CallBack UserCall) {
                //根据PID取得进程句柄
                IntPtr ProcessHandle;
                try {
                    ProcessHandle = Process.GetProcessById(DescProcess).Handle;
                } catch (Exception) {
                    return IntPtr.Zero;
                    throw;
                }

                //计算所需要的内存
                int oldDllLength = DllPath.Length;
                DllPath = string.Format("{0}\0", DllPath);
                byte[] buffer = Encoding.Default.GetBytes(DllPath.ToArray());
                int DllLength = buffer.Length;

                //申请内存空间
                IntPtr Baseaddress = VirtualAllocEx(ProcessHandle, 0, DllLength, 4096, 4);
                if (Baseaddress == IntPtr.Zero) return IntPtr.Zero;

                //写入内存
                int WriteOk = WriteProcessMemory(ProcessHandle, Baseaddress, DllPath, DllLength, 0);
                if (WriteOk == 0) return IntPtr.Zero;

                //获取模块句柄/函数入口
                IntPtr mHandle = GetModuleHandle("kernel32");
                if (mHandle == IntPtr.Zero) return IntPtr.Zero;
                IntPtr hack = GetProcAddress(mHandle, "LoadLibraryA");
                if (hack == IntPtr.Zero) return IntPtr.Zero;

                //创建远程线程
                IntPtr handle = CreateRemoteThread(ProcessHandle, 0, 0, hack, Baseaddress, flags, 0);
                if (handle == IntPtr.Zero) return IntPtr.Zero;

                //保存参数
                UserFun = UserCall;
                ProcessPid = DescProcess;
                hProcess = ProcessHandle;
                Memory = Baseaddress;
                hThread = handle;
                fFullName = DllPath.Replace("\0", "");

                //新建线程，用于等待注入线程结束
                Thread tWait = new Thread(ColseThread);
                tWait.Start();

                return handle;
            }

            /// <summary>
            /// 恢复注入线程的运行
            /// </summary>
            /// <returns>返回一个布尔型，表示成功和失败</returns>
            public bool ResumeThread() {
                //恢复线程，返回线程挂起计数，如果失败返回（-1）
                int Count = ResumeThread(hThread);
                return Count != -1;
            }

            /// <summary>
            /// 挂起注入的线程
            /// </summary>
            /// <returns>返回一个布尔型，表示成功和失败</returns>
            public bool SuspendThread() {
                //恢复线程，返回线程挂起计数，如果失败返回（-1）
                int Count = SuspendThread(hThread);
                return Count != -1;
            }

            /// <summary>
            /// 等待线程有信号
            /// </summary>
            private hState WaitThreadSignal() {
                //uint WAIT_FAILED = 0xFFFFFFFF;
                int Result = WaitForSingleObject(hThread, -1);
                return (hState)Result;
            }

            /// <summary>
            /// 清理已经结束的线程
            /// </summary>
            /// <returns></returns>
            private void ColseThread() {
                bool Result;

                //获取线程状态
                hState sThread = WaitThreadSignal();
                if (sThread != hState.WAIT_OBJECT_0) {
                    Result = false;
                } else {
                    //获取线程退出码
                    IntPtr ExitCode = GetExitCode();

                    //释放线程资源
                    Result = ResourcesFree(ExitCode);
                }
                try {

                    //运行回调函数
                    if (UserFun == null) return;
                    IAsyncResult uResult = UserFun.BeginInvoke(Result, delegate(IAsyncResult ar) {
                        UserFun.EndInvoke(ar);
                    }, null);
                    // 执行50毫秒后超时
                    uResult.AsyncWaitHandle.WaitOne(50 ,true);
                    
                } catch (Exception) {
                }
            }

            /// <summary>
            /// 获取注入线程的退出码
            /// </summary>
            /// <returns>返回一个IntPtr指针</returns>
            private IntPtr GetExitCode() {
                IntPtr ExitCode = new IntPtr();
                if (Environment.Is64BitProcess) {
                    //根据PID找到进程并枚举模块
                    try {
                        Process DescProcess = Process.GetProcessById(ProcessPid);
                        string ModuleName = Path.GetFileName(fFullName);
                        foreach (ProcessModule Module in DescProcess.Modules) {
                            if (ModuleName == Module.ModuleName) {
                                ExitCode = Module.BaseAddress;
                                break;
                            }

                        }
                    } catch (Exception) {
                        return IntPtr.Zero;
                        throw;
                    }

                } else {
                    //获取线程退出码
                    int Result = GetExitCodeThread(hThread, out ExitCode);
                }
                return ExitCode;
            }

            /// <summary>
            /// 释放线程资源
            /// </summary>
            /// <returns>返回结果表示此程序运行结果\n不表示资源释放成功</returns>
            private bool ResourcesFree(IntPtr ExitCode) {
                //释放内存
                //MEM_RELEASE = 0x8000;//释放申请的全部内存
                bool MemoryFree = VirtualFreeEx(hProcess, Memory, 0, 0x8000);

                //获取模块句柄
                IntPtr mHandle = GetModuleHandle("kernel32");
                if (mHandle == IntPtr.Zero) return false;

                //获取函数入口
                IntPtr hack = GetProcAddress(mHandle, "FreeLibrary");
                if (hack == IntPtr.Zero) return false;

                //创建远程线程,卸载模块
                IntPtr handle = CreateRemoteThread(hProcess, 0, 0, hack, ExitCode, 0, 0); ;

                //创建远程线程失败
                if (handle == IntPtr.Zero) return false;

                //等待线程有信号
                hState sThread = WaitThreadSignal();
                if (sThread != hState.WAIT_OBJECT_0) return false;

                //关闭句柄
                CloseHandle(hThread);
                CloseHandle(handle);

                return true;
            }
        }
    }
}
// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"
#include <fstream> // c++ �ļ�IOͷ
using namespace std;

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
							   char* path = "Injection.txt"; // ��Ҫ�����ļ���·��
							   ofstream fout(path);
							   if (fout) { // ��������ɹ�
								   fout << "�ˣ�����ע���Զ���߳�." << endl; // ʹ����coutͬ���ķ�ʽ����д��
								   fout.close();  // ִ���������ر��ļ����
							   }
							   MessageBox(0, TEXT("������ DLL_PROCESS_ATTACH"), TEXT("�߳�ע��"), 0);
	}
	case DLL_THREAD_ATTACH:
		//MessageBox(0, TEXT("������ DLL_THREAD_ATTACH"), TEXT("�߳�ע��"), 0);
	case DLL_THREAD_DETACH:
		//MessageBox(0, TEXT("������ DLL_THREAD_DETACH"), TEXT("�߳�ע��"), 0);
	case DLL_PROCESS_DETACH:
		//MessageBox(0, TEXT("������ DLL_PROCESS_DETACH"), TEXT("�߳�ע��"), 0);
		break;
	}
	return TRUE;
}


#include <Windows.h>
#include <iostream>

/* ��ȡ�ڴ� */
#define Read CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ALL_ACCESS)

/* д���ڴ� */
#define Write CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ALL_ACCESS)

const  char* g_link = "\\??\\SFeather";

/* ������Ϣ�Ľṹ */
typedef struct _UserData
{
	DWORD Pid;							//Ҫ��д�Ľ���ID
	DWORD64 Address;				//Ҫ��д�ĵ�ַ
	DWORD Size;							//��д����
	PBYTE Data;								//Ҫ��д������
}UserData, * PUserData;

HANDLE hDriver = NULL;

template<class T>
T read(DWORD pid, DWORD64 addr)
{
	T result{};

	UserData buf{ 0 };
	buf.Pid = pid;
	buf.Address = addr;
	buf.Data = (PBYTE)&result;
	buf.Size = sizeof(T);

	DWORD dwSize = 0;
	DeviceIoControl(hDriver, Read, &buf, sizeof(buf), &buf, sizeof(buf), &dwSize, NULL);

	return result;
}

template<class T>
void write(DWORD pid, DWORD64 addr, T value)
{
	UserData buf{ 0 };
	buf.Pid = pid;
	buf.Address = addr;
	buf.Data = (PBYTE)&value;
	buf.Size = sizeof(T);

	DWORD dwSize = 0;
	DeviceIoControl(hDriver, Write, &buf, sizeof(buf), &buf, sizeof(buf), &dwSize, NULL);
}

void test()
{
	hDriver = CreateFileA(g_link,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hDriver == INVALID_HANDLE_VALUE)
	{
		printf("[-]%d \n", GetLastError());
		return;
	}

	int data = read<int>(9400, 0xBF8624D33C);
	printf("[+]  : %d \n", data);
	int k = 0;
	std::cin >> k;
	write<int>(9400, 0xBF8624D33C, k);

	CloseHandle(hDriver);
	system("pause");

}

int main(int argc, char* argv[])
{
	test();

	system("pause");
	return 0;
}
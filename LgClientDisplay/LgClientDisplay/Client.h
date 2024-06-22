#pragma once
bool ConnectToSever(const char* remotehostname, unsigned short remoteport);
bool StartClient(void);
bool StopClient(void);
bool IsClientConnected(void);
bool SendCodeToSever(unsigned char Code);
bool SendTargetOrderToSever(char *TargetOrder);
bool SendPreArmCodeToSever(char* Code);
bool SendStateChangeRequestToSever(SystemState_t State);
bool SendCalibToSever(unsigned char Code);
bool SendLoginEnrollToSever(const char* userId, const char* userPw);
bool SendLoginVerifyToSever(const char* userId, const char* userPw);
bool SendLoginChangePwToSever(const char* userId, const char* userPw);
const char* getHmac(const char* body);
//bool GetStoredCredential(const wchar_t* targetName, std::wstring& username, std::wstring& password);
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------
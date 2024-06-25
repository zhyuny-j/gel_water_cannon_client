#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <atlstr.h>
#include <cstdlib >
#include <opencv2\highgui\highgui.hpp>
#include <opencv2\opencv.hpp>
#include "Message.h"
#include "Client.h"
#include "LgClientDisplay.h"
#include "TcpSendRecv.h"
#include "DisplayImage.h"
#include "CryptogramUtil.h"


#include <wincrypt.h>
//#include <wincred.h>
#include <iostream>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "Logger.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
//#pragma comment(lib, "advapi32.lib")

#define CA_CERT_FILE "ca.crt.pem"
#define CLIENT_CERT_FILE "client.crt.pem"
#define CLIENT_KEY_FILE "client.key.pem"

enum InputMode { MsgHeader, Msg };
static  std::vector<uchar> sendbuff;//buffer for coding
static HANDLE hClientEvent = INVALID_HANDLE_VALUE;
static HANDLE hEndClientEvent = INVALID_HANDLE_VALUE;
static SOCKET Client = INVALID_SOCKET;
static cv::Mat ImageIn;
static DWORD ThreadClientID;
static HANDLE hThreadClient = INVALID_HANDLE_VALUE;

static DWORD WINAPI ThreadClient(LPVOID ivalue);
static void ClientSetExitEvent(void);
static void ClientCleanup(void);

SSL* ssl;

char* token = new char[32];
unsigned long long clientSequenceNumber = 0L;
unsigned long long serverSequenceNumber = 0L;
bool isInitSequenceNumber = false;


SSL_CTX* InitCTX() {
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == nullptr) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	// Set TLS Version to TLSv1.2
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
	return ctx;
}


static void ClientSetExitEvent(void)
{
	if (hEndClientEvent != INVALID_HANDLE_VALUE)
		SetEvent(hEndClientEvent);
}
static void ClientCleanup(void)
{
	std::cout << "ClientCleanup" << std::endl;

	if (hClientEvent != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hClientEvent);
		hClientEvent = INVALID_HANDLE_VALUE;
	}
	if (hEndClientEvent != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hEndClientEvent);
		hEndClientEvent = INVALID_HANDLE_VALUE;
	}
	if (Client != INVALID_SOCKET)
	{
		closesocket(Client);
		Client = INVALID_SOCKET;
	}
}
bool SendCodeToSever(unsigned char Code)
{
	if (IsClientConnected())
	{
		TMesssageCommands MsgCmd;
		memset(&MsgCmd, 0, sizeof(TMesssageCommands));
		int msglen = sizeof(TMesssageHeader) + sizeof(MsgCmd.Commands) + sizeof(MsgCmd.Token);
		//printf("Message len %d\n", msglen);
		MsgCmd.Hdr.Len = htonl(sizeof(MsgCmd.Commands) + sizeof(MsgCmd.Token));
		MsgCmd.Hdr.Type = htonl(MT_COMMANDS);
		MsgCmd.Hdr.SeqNum = htonll(getClientSequenceNumber());

		MsgCmd.Commands = Code;
		
		memcpy(MsgCmd.Token, token, sizeof(MsgCmd.Token));
		int bodySize = sizeof(MsgCmd.Commands) + sizeof(MsgCmd.Token);
		setHmacValue(MsgCmd.Hdr.HMAC, sizeof(MsgCmd.Hdr.HMAC), reinterpret_cast<const char*>(&MsgCmd.Commands), bodySize);

		if (WriteDataTcp(ssl, (unsigned char*)&MsgCmd, msglen) == msglen)
		{
			printLog(LogLevel::DEBUG, "[SND] type: MT_COMMANDS, length: " + std::to_string(msglen));
			return true;
		}

	}
	return false;
}

bool SendCalibToSever(unsigned char Code)
{
	if (IsClientConnected())
	{
		TMesssageCalibCommands MsgCmd;
		memset(&MsgCmd, 0, sizeof(TMesssageCommands));
		int msglen = sizeof(TMesssageHeader) + sizeof(MsgCmd.Commands) + sizeof(MsgCmd.Token);
		//printf("Message len %d\n", msglen);
		MsgCmd.Hdr.Len = htonl(sizeof(MsgCmd.Commands) + sizeof(MsgCmd.Token));
		MsgCmd.Hdr.Type = htonl(MT_CALIB_COMMANDS);
		MsgCmd.Hdr.SeqNum = htonll(getClientSequenceNumber());

		MsgCmd.Commands = Code;
		memcpy(MsgCmd.Token, token, sizeof(MsgCmd.Token));

		int bodySize = sizeof(MsgCmd.Commands) + sizeof(MsgCmd.Token);
		setHmacValue(MsgCmd.Hdr.HMAC, sizeof(MsgCmd.Hdr.HMAC), reinterpret_cast<const char*>(&MsgCmd.Commands), bodySize);

		if (WriteDataTcp(ssl, (unsigned char*)&MsgCmd, msglen) == msglen)
		{
			printLog(LogLevel::DEBUG, "[SND] type: MT_CALIB_COMMANDS, length: " + std::to_string(msglen));
			return true;
		}

	}
	return false;
}

bool SendTargetOrderToSever(char* TargetOrder)
{
	if (IsClientConnected())
	{
		TMesssageTargetOrder MsgTargetOrder;
		memset(&MsgTargetOrder, 0, sizeof(TMesssageTargetOrder));
		int msglen = sizeof(TMesssageHeader) + sizeof(MsgTargetOrder.FiringOrder) + sizeof(MsgTargetOrder.Token);
		MsgTargetOrder.Hdr.Len = htonl(sizeof(MsgTargetOrder.FiringOrder) + sizeof(MsgTargetOrder.Token));
		MsgTargetOrder.Hdr.Type = htonl(MT_TARGET_SEQUENCE);
		MsgTargetOrder.Hdr.SeqNum = htonll(getClientSequenceNumber());

		strcpy_s((char*)MsgTargetOrder.FiringOrder, sizeof(MsgTargetOrder.FiringOrder), TargetOrder);
		memcpy(MsgTargetOrder.Token, token, sizeof(MsgTargetOrder.Token));

		int bodySize = sizeof(MsgTargetOrder.FiringOrder) + sizeof(MsgTargetOrder.Token);
		setHmacValue(MsgTargetOrder.Hdr.HMAC, sizeof(MsgTargetOrder.Hdr.HMAC), MsgTargetOrder.FiringOrder, bodySize);

		if (WriteDataTcp(ssl, (unsigned char*)&MsgTargetOrder, msglen) == msglen)
		{
			printLog(LogLevel::DEBUG, "[SND] type: MT_TARGET_SEQUENCE, length: " + std::to_string(msglen));
			return true;
		}
	}
	return false;
}

bool SendPreArmCodeToSever(char* Code)
{
	if (IsClientConnected())
	{
		TMesssagePreArm MsgPreArm;
		memset(&MsgPreArm, 0, sizeof(TMesssagePreArm));
		int msglen = sizeof(TMesssageHeader) + sizeof(MsgPreArm.Code) + sizeof(MsgPreArm.Token);
		MsgPreArm.Hdr.Len = htonl(sizeof(MsgPreArm.Code) + sizeof(MsgPreArm.Token));
		MsgPreArm.Hdr.Type = htonl(MT_PREARM);
		MsgPreArm.Hdr.SeqNum = htonll(getClientSequenceNumber());

		strcpy_s((char*)MsgPreArm.Code, sizeof(MsgPreArm.Code), Code);
		memcpy(MsgPreArm.Token, token, sizeof(MsgPreArm.Token));

		int bodySize = sizeof(MsgPreArm.Code) + sizeof(MsgPreArm.Token);
		setHmacValue(MsgPreArm.Hdr.HMAC, sizeof(MsgPreArm.Hdr.HMAC), MsgPreArm.Code, bodySize);

		if (WriteDataTcp(ssl, (unsigned char*)&MsgPreArm, msglen) == msglen)
		{
			printLog(LogLevel::DEBUG, "[SND] type: MT_PREARM, length: " + std::to_string(msglen));
			return true;
		}

	}
	return false;
}

bool SendStateChangeRequestToSever(SystemState_t State)
{
	if (IsClientConnected())
	{
		TMesssageChangeStateRequest MsgChangeStateRequest;
		memset(&MsgChangeStateRequest, 0, sizeof(TMesssageChangeStateRequest));
		int msglen = sizeof(TMesssageChangeStateRequest) + sizeof(MsgChangeStateRequest.Token);
		MsgChangeStateRequest.Hdr.Len = htonl(sizeof(MsgChangeStateRequest.State) + sizeof(MsgChangeStateRequest.Token));
		MsgChangeStateRequest.Hdr.Type = htonl(MT_STATE_CHANGE_REQ);
		MsgChangeStateRequest.Hdr.SeqNum = htonll(getClientSequenceNumber());

		MsgChangeStateRequest.State = (SystemState_t)htonl(State);
		memcpy(MsgChangeStateRequest.Token, token, sizeof(MsgChangeStateRequest.Token));

		int bodySize = sizeof(MsgChangeStateRequest.State) + sizeof(MsgChangeStateRequest.Token);
		setHmacValue(MsgChangeStateRequest.Hdr.HMAC, sizeof(MsgChangeStateRequest.Hdr.HMAC), reinterpret_cast<const char*>(&MsgChangeStateRequest.State), bodySize);

		if (WriteDataTcp(ssl, (unsigned char*)&MsgChangeStateRequest, msglen) == msglen)
		{
			printLog(LogLevel::DEBUG, "[SND] type: MT_STATE_CHANGE_REQ, length: " + std::to_string(msglen));
			return true;
		}

	}
	return false;
}

bool SendLoginEnrollToSever(const char* userId, const char* userPw)
{
	if (IsClientConnected())
	{
		std::cout << "SendLoginEnrollToSever" << std::endl;
		TMesssageLoginEnrollRequest MsgLoginEnroll;
		memset(&MsgLoginEnroll, 0, sizeof(TMesssageLoginEnrollRequest));
		int msglen = sizeof(TMesssageHeader) + (int)sizeof(MsgLoginEnroll.Name) + (int)sizeof(MsgLoginEnroll.Password);

		MsgLoginEnroll.Hdr.Len = htonl((int)sizeof(MsgLoginEnroll.Name) + (int)sizeof(MsgLoginEnroll.Password));
		MsgLoginEnroll.Hdr.Type = htonl(MT_LOGIN_ENROLL_REQ);
		MsgLoginEnroll.Hdr.SeqNum = htonll(getClientSequenceNumber());

		memoryCopyAndMemset(MsgLoginEnroll.Name, sizeof(MsgLoginEnroll.Name), userId);
		memoryCopyAndMemset(MsgLoginEnroll.Password, sizeof(MsgLoginEnroll.Password), userPw);

		int bodySize = sizeof(MsgLoginEnroll.Name) + sizeof(MsgLoginEnroll.Password);
		setHmacValue(MsgLoginEnroll.Hdr.HMAC, sizeof(MsgLoginEnroll.Hdr.HMAC), MsgLoginEnroll.Name, bodySize);

		if (WriteDataTcp(ssl, (unsigned char*)&MsgLoginEnroll, msglen) == msglen)
		{
			printLog(LogLevel::DEBUG, "[SND] type: MT_LOGIN_ENROLL_REQ, length: " + std::to_string(msglen));
			return true;
		}

	}
	return false;
}

bool SendLoginVerifyToSever(const char* userId, const char* userPw)
{
	if (IsClientConnected())
	{
		std::cout << "SendLoginVerifyToSever" << std::endl;
		
		TMesssageLoginVerifyRequest MsgLoginVerify;
		memset(&MsgLoginVerify, 0, sizeof(TMesssageLoginVerifyRequest));
		int msglen = sizeof(TMesssageHeader) + (int)sizeof(MsgLoginVerify.Name) + (int)sizeof(MsgLoginVerify.Password);

		MsgLoginVerify.Hdr.Len = htonl((int)sizeof(MsgLoginVerify.Name) + (int)sizeof(MsgLoginVerify.Password));
		MsgLoginVerify.Hdr.Type = htonl(MT_LOGIN_VERITY_REQ);
		MsgLoginVerify.Hdr.SeqNum = htonll(getClientSequenceNumber());

		memoryCopyAndMemset(MsgLoginVerify.Name, sizeof(MsgLoginVerify.Name), userId);
		memoryCopyAndMemset(MsgLoginVerify.Password, sizeof(MsgLoginVerify.Password), userPw);

		int bodySize = sizeof(MsgLoginVerify.Name) + sizeof(MsgLoginVerify.Password);
		setHmacValue(MsgLoginVerify.Hdr.HMAC, sizeof(MsgLoginVerify.Hdr.HMAC), MsgLoginVerify.Name, bodySize);

		if (WriteDataTcp(ssl, (unsigned char*)&MsgLoginVerify, msglen) == msglen)
		{
			printLog(LogLevel::DEBUG, "[SND] type: MT_LOGIN_VERITY_REQ, length: " + std::to_string(msglen));
			return true;
		}

	}
	return false;
}

bool SendLoginChangePwToSever(const char* userId, const char* userPw)
{
	if (IsClientConnected())
	{
		std::cout << "SendLoginChangePwToSever" << std::endl;

		TMesssageLoginChangePwRequest MsgLoginChangePw;
		memset(&MsgLoginChangePw, 0, sizeof(TMesssageLoginChangePwRequest));
		int msglen = sizeof(TMesssageHeader) + (int)sizeof(MsgLoginChangePw.Name) + (int)sizeof(MsgLoginChangePw.Password) + (int)sizeof(MsgLoginChangePw.Token);

		MsgLoginChangePw.Hdr.Len = htonl((int)sizeof(MsgLoginChangePw.Name) + (int)sizeof(MsgLoginChangePw.Password) + (int)sizeof(MsgLoginChangePw.Token));
		MsgLoginChangePw.Hdr.Type = htonl(MT_LOGIN_CHANGEPW_REQ);
		MsgLoginChangePw.Hdr.SeqNum = htonll(getClientSequenceNumber());

		memoryCopyAndMemset(MsgLoginChangePw.Name, sizeof(MsgLoginChangePw.Name), userId);
		memoryCopyAndMemset(MsgLoginChangePw.Password, sizeof(MsgLoginChangePw.Password), userPw);
		memoryCopyAndMemset(MsgLoginChangePw.Token, sizeof(MsgLoginChangePw.Token), token);

		int bodySize = sizeof(MsgLoginChangePw.Name) + sizeof(MsgLoginChangePw.Password) + sizeof(MsgLoginChangePw.Token);
		setHmacValue(MsgLoginChangePw.Hdr.HMAC, sizeof(MsgLoginChangePw.Hdr.HMAC), MsgLoginChangePw.Name, bodySize);

		if (WriteDataTcp(ssl, (unsigned char*)&MsgLoginChangePw, msglen) == msglen)
		{
			printLog(LogLevel::DEBUG, "[SND] type: MT_LOGIN_CHANGEPW_REQ, length: " + std::to_string(msglen));
			return true;
		}

	}
	return false;
}

bool SendLogoutToSever() {
	if (IsClientConnected())
	{
		std::cout << "SendLogoutToSever" << std::endl;

		TMesssageLogoutRequest MsgLogout;
		memset(&MsgLogout, 0, sizeof(TMesssageLogoutRequest));
		int msglen = sizeof(TMesssageHeader) + sizeof(MsgLogout.Token);

		MsgLogout.Hdr.Len = htonl(sizeof(MsgLogout.Token));
		MsgLogout.Hdr.Type = htonl(MT_LOGOUT_REQ);
		MsgLogout.Hdr.SeqNum = htonll(getClientSequenceNumber());

		memoryCopyAndMemset(MsgLogout.Token, sizeof(MsgLogout.Token), token);

		int bodySize = sizeof(MsgLogout.Token);
		setHmacValue(MsgLogout.Hdr.HMAC, sizeof(MsgLogout.Hdr.HMAC), MsgLogout.Token, bodySize);

		if (WriteDataTcp(ssl, (unsigned char*)&MsgLogout, msglen) == msglen)
		{
			printLog(LogLevel::DEBUG, "[SND] type: MT_LOGOUT_REQ, length: " + std::to_string(msglen));
			return true;
		}
	}
	return false;
}


bool ConnectToSever(const char* remotehostname, unsigned short remoteport)
{
	int iResult;
	struct addrinfo   hints;
	struct addrinfo* result = NULL;
	char remoteportno[128];
	initLogger("gel_water_blaster_cannon_client.log");
	SSL_CTX* ctx = InitCTX();

	// Load server key and CRT
	if (SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, nullptr) <= 0) {
		std::cerr << "Error setting CA certificate" << std::endl;
		return false;
	}

	if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
		std::cerr << "Error loading server certificate." << std::endl;
		return false;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		std::cerr << "Error loading server private key." << std::endl;
		return false;
	}

	sprintf_s(remoteportno, sizeof(remoteportno), "%d", remoteport);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	iResult = getaddrinfo(remotehostname, remoteportno, &hints, &result);
	if (iResult != 0)
	{
		std::cout << "getaddrinfo: Failed" << std::endl;
		return false;
	}
	if (result == NULL)
	{
		std::cout << "getaddrinfo: Failed" << std::endl;
		return false;
	}

	if ((Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)

	{
		freeaddrinfo(result);
		std::cout << "video client socket() failed with error " << WSAGetLastError() << std::endl;
		return false;
	}

	//----------------------
	// Connect to server.
	iResult = connect(Client, result->ai_addr, (int)result->ai_addrlen);
	freeaddrinfo(result);
	if (iResult == SOCKET_ERROR) {
		std::cout << "connect function failed with error : " << WSAGetLastError() << std::endl;
		iResult = closesocket(Client);
		Client = INVALID_SOCKET;
		if (iResult == SOCKET_ERROR)
			std::cout << "closesocket function failed with error :" << WSAGetLastError() << std::endl;
		return false;
	}
	int yes = 1;
	iResult = setsockopt(Client,
		IPPROTO_TCP,
		TCP_NODELAY,
		(char*)&yes,
		sizeof(int));    // 1 - on, 0 - off
	if (iResult < 0)
	{
		printf("TCP NODELAY Failed\n");
	}
	else  printf("TCP NODELAY SET\n");

	// SSL socket create
	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		std::cerr << "Error creating SSL structure." << std::endl;
		closesocket(Client);
		return false;
	}
	SSL_set_fd(ssl, Client);

	// SSL Handshake
	if (SSL_connect(ssl) != 1) {
		std::cerr << "Error establishing SSL connection." << std::endl;
		SSL_free(ssl);
		closesocket(Client);
		return false;
	}

	return true;

}

void setHmacValue(char* headerHmac, int sizeOfHmac, const char* body, int bodySize) {
	unsigned char* encryptedBody = encryptBodyWithHMac(body, bodySize);
	memcpy(headerHmac, encryptedBody, sizeOfHmac);
}

bool checkHmacValidation(char* headerHmac, int sizeOfHmac, const char* body, int bodySize) {
	unsigned char* encryptedBody = encryptBodyWithHMac(body, bodySize);
	return memcmp(headerHmac, encryptedBody, sizeOfHmac) == 0;
}

bool checkSequenceNumberValidation(unsigned long long receivedSequenceNumber) {
	if (!isInitSequenceNumber) {
		serverSequenceNumber = receivedSequenceNumber;
		isInitSequenceNumber = true;
		return true;
	}
	if (serverSequenceNumber >= receivedSequenceNumber) {
		printf("[checkSequenceNumberValidation] Invalid sequence number: %llu. Drop the message.\n", receivedSequenceNumber);
		return false;
	}
	serverSequenceNumber = receivedSequenceNumber;
	return true;
}

unsigned long long getClientSequenceNumber() {
	return ++clientSequenceNumber;
}


void memoryCopyAndMemset(char* destnation, int sizeOfDestination, const char* source) {
	strcpy_s(destnation, sizeOfDestination, source);
	memset(destnation + strlen(destnation), 0, sizeOfDestination - strlen(destnation));
}

bool StartClient(void)
{
	hThreadClient = CreateThread(NULL, 0, ThreadClient, NULL, 0, &ThreadClientID);
	return true;
}

bool StopClient(void)
{
	ClientSetExitEvent();
	if (hThreadClient != INVALID_HANDLE_VALUE)
	{
		WaitForSingleObject(hThreadClient, INFINITE);
		CloseHandle(hThreadClient);
		hThreadClient = INVALID_HANDLE_VALUE;
	}
	;
	return true;
}
bool IsClientConnected(void)
{
	if (hThreadClient == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	else return true;
}
void ProcessMessage(char* MsgBuffer)
{
	int messageLength = strlen(MsgBuffer) -1 ;

	TMesssageHeader* MsgHdr;
	MsgHdr = (TMesssageHeader*)MsgBuffer;
	MsgHdr->Len = ntohl(MsgHdr->Len);
	MsgHdr->Type = ntohl(MsgHdr->Type);
	MsgHdr->SeqNum = htonll(MsgHdr->SeqNum);

	if (!checkSequenceNumberValidation(MsgHdr->SeqNum)) {
		return;
	}

	switch (MsgHdr->Type)
	{
	case MT_IMAGE:
	{
		cv::imdecode(cv::Mat(MsgHdr->Len, 1, CV_8UC1, MsgBuffer + sizeof(TMesssageHeader)), cv::IMREAD_COLOR, &ImageIn);
		ProcessImage(ImageIn);
	}
	break;
	case MT_TEXT:
	{
		CStringW cstring(MsgBuffer + sizeof(TMesssageHeader));
		PRINT(_T("%s\r\n"), cstring);
	}
	break;
	case MT_STATE:
	{
		printLog(LogLevel::DEBUG, "[RCV] type: TMesssageSystemState, length: " + std::to_string(messageLength));
		TMesssageSystemState* MsgState;
		MsgState = (TMesssageSystemState*)MsgBuffer;
		MsgState->State = (SystemState_t)ntohl(MsgState->State);
		PostMessage(hWndMain, WM_SYSTEM_STATE, MsgState->State, 0);

	}
	break;
	case MT_LOGIN_ENROLL_RES:
	{
		printLog(LogLevel::DEBUG, "[RCV] type: MT_LOGIN_ENROLL_RES, length: " + std::to_string(messageLength));
		TMesssageLoginEnrollResponse* MsgLoginEnrolRes;
		MsgLoginEnrolRes = (TMesssageLoginEnrollResponse*)MsgBuffer;
		MsgLoginEnrolRes->LoginState = (LogInState_t)ntohl(MsgLoginEnrolRes->LoginState);
		int bodySize = sizeof(MsgLoginEnrolRes->LoginState);
		char messageByte[sizeof(unsigned int)];
		std::memcpy(&messageByte, &MsgLoginEnrolRes->LoginState, sizeof(unsigned int));
		if (!checkHmacValidation(MsgHdr->HMAC, sizeof(MsgHdr->HMAC), messageByte, bodySize)) {
			printf("The HMAC value of LoginEnrollResponse is invalid. Drop the message");
		}
		PostMessage(hWndMain, WM_LOGIN_STATE, MsgLoginEnrolRes->LoginState, 0);

	}
	break;
	case MT_LOGIN_VERITY_RES:
	{
		printLog(LogLevel::DEBUG, "[RCV] type: MT_LOGIN_VERITY_RES, length: " + std::to_string(messageLength));
		TMesssageLoginVerifyResponse* MsgLoginVerifyRes;
		MsgLoginVerifyRes = (TMesssageLoginVerifyResponse*)MsgBuffer;
		MsgLoginVerifyRes->LoginState = (LogInState_t)ntohl(MsgLoginVerifyRes->LoginState);
		int bodySize = sizeof(MsgLoginVerifyRes->LoginState) + sizeof(MsgLoginVerifyRes->FailCount) +
			sizeof(MsgLoginVerifyRes->Throttle) + sizeof(MsgLoginVerifyRes->Privilige) + sizeof(MsgLoginVerifyRes->Token);
		if (!checkHmacValidation(MsgHdr->HMAC, sizeof(MsgHdr->HMAC), reinterpret_cast<const char*>(&MsgLoginVerifyRes->LoginState), bodySize)) {
			printf("The HMAC value of LoginVerifyResponse is invalid. Drop the message");
		}
		PostMessage(hWndMain, WM_LOGIN_STATE, MsgLoginVerifyRes->LoginState, 0);
		if (LogInState_t::SUCCESS != MsgLoginVerifyRes->LoginState) {
			PostMessage(hWndMain, WM_LOGIN_FAIL_COUNT, MsgLoginVerifyRes->FailCount, 0);
			PostMessage(hWndMain, WM_LOGIN_THROTTLE, MsgLoginVerifyRes->Throttle, 0);
		}
		else {
			memcpy(token, MsgLoginVerifyRes->Token, sizeof(MsgLoginVerifyRes->Token));
			PostMessage(hWndMain, WM_LOGIN_PRIVILEGE, MsgLoginVerifyRes->Privilige, 0);
		}
	}
	break;
	case MT_LOGIN_CHANGEPW_RES:
	{
		printLog(LogLevel::DEBUG, "[RCV] type: MT_LOGIN_CHANGEPW_RES, length: " + std::to_string(messageLength));
		TMesssageLoginChangePwResponse* MsgLoginChangePwRes;
		MsgLoginChangePwRes = (TMesssageLoginChangePwResponse*)MsgBuffer;
		MsgLoginChangePwRes->LoginState = (LogInState_t)ntohl(MsgLoginChangePwRes->LoginState);
		int bodySize = sizeof(MsgLoginChangePwRes->LoginState);
		char messageByte[sizeof(unsigned int)];
		std::memcpy(&messageByte, &MsgLoginChangePwRes->LoginState, sizeof(unsigned int));
		if (!checkHmacValidation(MsgHdr->HMAC, sizeof(MsgHdr->HMAC), messageByte, bodySize)) {
			printf("The HMAC value of MsgLoginChangePwRes is invalid. Drop the message");
		}
		PostMessage(hWndMain, WM_LOGIN_STATE, MsgLoginChangePwRes->LoginState, 0);
	}
	break;
	case MT_SHARED_HMAC_KEY:
	{
		printLog(LogLevel::DEBUG, "[RCV] type: MT_SHARED_HMAC_KEY, length: " + std::to_string(messageLength));
		TMesssageSharedHmacKey* MsgSharedHmacKey;
		MsgSharedHmacKey = (TMesssageSharedHmacKey*)MsgBuffer;

		setHmacKey(MsgSharedHmacKey->SharedKey, MsgHdr->Len);
		
	}
	break;
	case MT_LOGOUT_RES:
	{
		printLog(LogLevel::DEBUG, "[RCV] type: MT_LOGOUT_RES, length: " + std::to_string(messageLength));
		TMesssageLogoutResponse* MsgLogoutRes;
		MsgLogoutRes = (TMesssageLogoutResponse*)MsgBuffer;
		MsgLogoutRes->LoginState = (LogInState_t)ntohl(MsgLogoutRes->LoginState);
		int bodySize = sizeof(MsgLogoutRes->LoginState);
		char messageByte[sizeof(unsigned int)];
		std::memcpy(&messageByte, &MsgLogoutRes->LoginState, sizeof(unsigned int));
		if (!checkHmacValidation(MsgHdr->HMAC, sizeof(MsgHdr->HMAC), messageByte, bodySize)) {
			printf("The HMAC value of LoginEnrollResponse is invalid. Drop the message");
			return;
		}
		//Initialize token
		for (int i = 0; i < strlen(token); i++) {
			token[i] = 0x00;
		}
		PostMessage(hWndMain, WM_LOGIN_STATE, MsgLogoutRes->LoginState, 0);
	}
	break;
	default:
	{
		printf("unknown message\n");
	}
	break;
	}
}

/*
bool GetStoredCredential(const wchar_t* targetName, std::wstring& username, std::wstring& password)
{
	PCREDENTIAL cred;
	if (!CredReadW(targetName, CRED_TYPE_GENERIC, 0, &cred))
	{
		std::cerr << "CredRead failed: " << GetLastError() << std::endl;
		return false;
	}

	if (cred->Type == CRED_TYPE_GENERIC)
	{
		username = std::wstring(cred->UserName);
		DATA_BLOB dataIn;
		DATA_BLOB dataOut;
		dataIn.cbData = cred->CredentialBlobSize;
		dataIn.pbData = cred->CredentialBlob;


		// 암호는 CredentialBlob에 저장되어 있으며, CredentialBlobSize에 크기가 저장되어 있음
		//if (cred->CredentialBlobSize > 0) {
		//    std::vector<char> password(cred->CredentialBlob, cred->CredentialBlob + cred->CredentialBlobSize);
		//    password.push_back('\0'); // null-terminator 추가

		//    std::wcout << L"Credential Password: " << (char*)password.data() << std::endl;
		//}


		if (CryptUnprotectData(&dataIn, nullptr, nullptr, nullptr, nullptr, 0, &dataOut))
		{
			password = std::wstring(reinterpret_cast<wchar_t*>(dataOut.pbData), dataOut.cbData / sizeof(wchar_t));
			LocalFree(dataOut.pbData);
			CredFree(cred);
			return true;
		}
		else
		{
			std::cerr << "CryptUnprotectData failed: " << GetLastError() << std::endl;
		}
	}

	CredFree(cred);
	return false;
}
*/


static DWORD WINAPI ThreadClient(LPVOID ivalue)
{
	HANDLE ghEvents[2];
	int NumEvents;
	int iResult;
	DWORD dwEvent;
	InputMode Mode = MsgHeader;
	unsigned int InputBytesNeeded = sizeof(TMesssageHeader);
	TMesssageHeader MsgHdr;
	char* InputBuffer = NULL;
	char* InputBufferWithOffset = NULL;
	unsigned int CurrentInputBufferSize = 1024 * 10;

	InputBuffer = (char*)std::realloc(InputBuffer, CurrentInputBufferSize);
	InputBufferWithOffset = InputBuffer;

	if (InputBuffer == NULL)
	{
		std::cout << "InputBuffer Realloc failed" << std::endl;
		ExitProcess(0);
		return 1;
	}

	hClientEvent = WSACreateEvent();
	hEndClientEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	if (WSAEventSelect(Client, hClientEvent, FD_READ | FD_CLOSE) == SOCKET_ERROR)

	{
		std::cout << "WSAEventSelect() failed with error " << WSAGetLastError() << std::endl;
		iResult = closesocket(Client);
		Client = INVALID_SOCKET;
		if (iResult == SOCKET_ERROR)
			std::cout << "closesocket function failed with error : " << WSAGetLastError() << std::endl;
		return 4;
	}
	ghEvents[0] = hEndClientEvent;
	ghEvents[1] = hClientEvent;
	NumEvents = 2;

	while (1) {
		dwEvent = WaitForMultipleObjects(
			NumEvents,        // number of objects in array
			ghEvents,       // array of objects
			FALSE,           // wait for any object
			INFINITE);  // INFINITE) wait

		if (dwEvent == WAIT_OBJECT_0) break;
		else if (dwEvent == WAIT_OBJECT_0 + 1)
		{
			WSANETWORKEVENTS NetworkEvents;
			if (SOCKET_ERROR == WSAEnumNetworkEvents(Client, hClientEvent, &NetworkEvents))
			{
				std::cout << "WSAEnumNetworkEvent: " << WSAGetLastError() << "dwEvent " << dwEvent << " lNetworkEvent " << std::hex << NetworkEvents.lNetworkEvents << std::endl;
				NetworkEvents.lNetworkEvents = 0;
			}
			else
			{
				if (NetworkEvents.lNetworkEvents & FD_READ)
				{
					if (NetworkEvents.iErrorCode[FD_READ_BIT] != 0)
					{
						std::cout << "FD_READ failed with error " << NetworkEvents.iErrorCode[FD_READ_BIT] << std::endl;
					}
					else
					{
						int iResult;
						iResult = ReadDataTcpNoBlock(ssl, (unsigned char*)InputBufferWithOffset, InputBytesNeeded);
						if (iResult != SOCKET_ERROR)
						{
							if (iResult == 0)
							{
								Mode = MsgHeader;
								InputBytesNeeded = sizeof(TMesssageHeader);
								InputBufferWithOffset = InputBuffer;
								PostMessage(hWndMain, WM_CLIENT_LOST, 0, 0);
								std::cout << "Connection closed on Recv" << std::endl;
								break;
							}
							else
							{
								InputBytesNeeded -= iResult;
								InputBufferWithOffset += iResult;
								if (InputBytesNeeded == 0)
								{
									if (Mode == MsgHeader)
									{

										InputBufferWithOffset = InputBuffer + sizeof(TMesssageHeader);
										memcpy(&MsgHdr, InputBuffer, sizeof(TMesssageHeader));
										MsgHdr.Len = ntohl(MsgHdr.Len);
										MsgHdr.Type = ntohl(MsgHdr.Type);
										InputBytesNeeded = MsgHdr.Len;
										Mode = Msg;
										if ((InputBytesNeeded + sizeof(TMesssageHeader)) > CurrentInputBufferSize)
										{
											CurrentInputBufferSize = InputBytesNeeded + sizeof(TMesssageHeader) + (10 * 1024);
											InputBuffer = (char*)std::realloc(InputBuffer, CurrentInputBufferSize);
											if (InputBuffer == NULL)
											{
												std::cout << "std::realloc failed " << std::endl;
												ExitProcess(0);
											}
											InputBufferWithOffset = InputBuffer + sizeof(TMesssageHeader);
										}

									}
									else if (Mode == Msg)
									{
										ProcessMessage(InputBuffer);
										// Setup for next message
										Mode = MsgHeader;
										InputBytesNeeded = sizeof(TMesssageHeader);
										InputBufferWithOffset = InputBuffer;
									}
								}

							}
						}
						//else std::cout << "ReadDataTcpNoBlock buff failed " << WSAGetLastError() << std::endl;

					}

				}
				if (NetworkEvents.lNetworkEvents & FD_WRITE)
				{
					if (NetworkEvents.iErrorCode[FD_WRITE_BIT] != 0)
					{
						std::cout << "FD_WRITE failed with error " << NetworkEvents.iErrorCode[FD_WRITE_BIT] << std::endl;
					}
					else
					{
						std::cout << "FD_WRITE" << std::endl;
					}
				}

				if (NetworkEvents.lNetworkEvents & FD_CLOSE)
				{
					if (NetworkEvents.iErrorCode[FD_CLOSE_BIT] != 0)

					{
						std::cout << "FD_CLOSE failed with error " << NetworkEvents.iErrorCode[FD_CLOSE_BIT] << std::endl;
					}
					else
					{
						std::cout << "FD_CLOSE" << std::endl;
						PostMessage(hWndMain, WM_CLIENT_LOST, 0, 0);
						break;
					}

				}
			}

		}
	}
	if (InputBuffer)
	{
		std::free(InputBuffer);
		InputBuffer = nullptr;
	}
	ClientCleanup();
	std::cout << "Client Exiting" << std::endl;
	return 0;
}
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------
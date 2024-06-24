// LgVideoChatDemo.cpp : Defines the entry point for the application.

#include "framework.h"
#include <Commctrl.h>
#include <atlstr.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <fcntl.h>
#include <mmsystem.h>
#include <opencv2\highgui\highgui.hpp>
#include <opencv2\opencv.hpp>
#include "LgClientDisplay.h"
#include "DisplayImage.h"
#include <Message.h>
#include "Client.h"
#include <cctype> // for isdigit and isalpha
#include <ctime> // for time_t and time functions

//#include <log4cpp/Category.hh>
//#include <log4cpp/Appender.hh>
//#include <log4cpp/FileAppender.hh>
//#include <log4cpp/OstreamAppender.hh>
//#include <log4cpp/PatternLayout.hh>

#pragma comment(lib,"comctl32.lib")
#ifdef _DEBUG
#pragma comment(lib,"..\\..\\..\\opencv\\build\\x64\\vc16\\lib\\opencv_world490d.lib")
#else
#pragma comment(lib,"..\\..\\..\\opencv\\build\\x64\\vc16\\lib\\opencv_world490.lib")
#endif
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")


#define MAX_LOADSTRING 100

#define MT_LOGIN_REQUEST          1001
#define MT_LOGIN_VERIFY_RES       1002

#define IDC_LABEL_REMOTE          1010
#define IDC_EDIT_REMOTE           1011
#define IDC_LABEL_ENGAGE_ORDER    1012
#define IDC_EDIT_ENGAGE_ORDER     1013
#define IDC_LABEL_PREARM_CODE     1014
#define IDC_EDIT_PREARM_CODE      1015
#define IDC_CHECKBOX_ARMED_MANUAL 1016 
#define IDC_CHECKBOX_LASER_ENABLE 1017 
#define IDC_CHECKBOX_AUTO_ENGAGE  1018 
#define IDC_CHECKBOX_CALIBRATE    1019
#define IDC_CHECKBOX_CAMERA_ENABLE 1020
#define IDC_CHECKBOX_LASER        1021
#define IDC_CHECKBOX_CAMERA       1022
#define IDC_BUTTON_PREARM_SAFE    1023 
#define IDC_BUTTON_SAFE           1024 
#define IDC_EDIT                  1025
#define IDM_CONNECT               1026
#define IDM_DISCONNECT            1027
#define IDC_LABEL_SYSTEM_STATE    1028
#define IDC_SYSTEM_STATE          1029

#define IDC_LABEL_ID              1030 // 추가
#define IDC_EDIT_ID               1031 // 추가
#define IDC_LABEL_PASSWORD        1032 // 추가
#define IDC_EDIT_PASSWORD         1033 // 추가
#define IDC_BUTTON_LOGIN          1034 // 추가
#define IDC_BUTTON_LOGOUT         1035 // 추가
#define IDC_BUTTON_REGISTER       1036 // 추가
#define IDC_LABEL_REGISTER_ID     1041 // ID 레이블
#define IDC_EDIT_REGISTER_ID      1042 // ID 입력 필드
#define IDC_LABEL_REGISTER_PASS   1043 // Password 레이블
#define IDC_EDIT_REGISTER_PASS    1044 // Password 입력 필드
#define IDC_BUTTON_CHANGE_PASSWORD 1045  // Change 버튼 필드
#define IDC_BUTTON_ADMIN_LOGIN     1046
#define IDC_LABEL_LOGGEDIN_AS      1047
#define IDC_STATIC_LOGGEDIN_ID     1047

#define PREFIRE_SOUND IDR_WAVE1
#define MAX_FAILED_ATTEMPTS       3
#define LOCK_DURATION             3600 // 1 hour in seconds

// Global Variables:
bool isLoggedIn = false;  // Check Login State
std::string loggedInUserID;

HWND hWndMain;
GUID InstanceGuid;

SystemState_t SystemState = SAFE;
static HINSTANCE hInst;                                // current instance
static WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
static WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

static char RemoteAddress[512] = "raspberrypi.local";
static char EngagementOrder[512] = "0123456789";
static char PreArmCode[512] = "";
static char ID[32] = ""; // 추가
static char Password[32] = "";
char currentUserId[32];

//static char SavedID[512] = "LG_Shiled"; // 저장된 ID
//static char SavedPassword[512] = "0123456789"; // 저장된 Password

static FILE* pCout = NULL;
static HWND hWndMainToolbar;
static HWND hWndEdit;

// Forward declarations of functions included in this code module:
static ATOM                MyRegisterClass(HINSTANCE hInstance);
static BOOL                InitInstance(HINSTANCE, int);
static LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
static INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

INT_PTR CALLBACK ChangePasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK AdminLoginDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

static int CountDups(char* string);
static LRESULT OnCreate(HWND, UINT, WPARAM, LPARAM);
static LRESULT OnSize(HWND, UINT, WPARAM, LPARAM);
static int OnConnect(HWND, UINT, WPARAM, LPARAM);
static int OnDisconnect(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
static int OnStartServer(HWND, UINT, WPARAM, LPARAM);
static int OnStopServer(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
static void SetStdOutToNewConsole(void);
//static void DisplayMessageOkBox(const char* Msg);
static bool OnlyOneInstance(void);
//bool IsAccountLocked(const std::string& userID);
//void RecordFailedAttempt(const std::string& userID);
bool IsValidPassword(const std::string& password);
void OnAdminLoginButtonClick(HWND hWnd);
void ShowLoggedInID(HWND hWnd, const char* id);
void OnRegistorButtonClick(HWND hWnd);
void DisplayMessageOkBox(const char* Msg);
//void RecordLockTime(const std::string& userID);
bool IsAccountLocked(unsigned int failCount);
void OnLoginButtonClick(HWND hWnd);
//void OnLogin(HWND hWnd);
//void OnLogout(HWND hWnd);
//void RegisterUser(HWND hWnd);
//bool SendLoginRequestToServer(const char* userId, const char* userPw);


// Mock function to check if client is connected
/*
bool IsClientConnected() {
    // This should be implemented to actually check the connection status
    return true;
}
*/
// Mock function to write data to the server using TCP
int WriteDataTcp(void* ssl, unsigned char* data, int length) {
    // This should be implemented to actually send data over TCP
    std::cout << "Sending data to server: " << std::string((char*)data, length) << std::endl;
    return length;
}

/*
struct AccountLockInfo {
    int failedAttempts;
    time_t lockTime;
};

AccountLockInfo accountLockInfo = { 0, 0 };

// 계정 정보 구조체
struct AccountInfo {
    std::string password;
    int failedAttempts;
    time_t lockTime;
};

// 글로벌 변수로 계정 정보 맵 선언
std::map<std::string, AccountInfo> accounts;
*/
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    WSADATA wsaData;
    HRESULT hr;

    SetStdOutToNewConsole();
    //InitializeAccounts(); // 계정 초기화

    int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != NO_ERROR) {
        std::cout << "WSAStartup failed with error " << res << std::endl;
        return 1;
    }
    //SetHostAddr();
    hr = CoCreateGuid(&InstanceGuid);
    if (hr != S_OK)
    {
        std::cout << "GUID Create Failure " << std::endl;
        return 1;
    }
    printf("Guid = {%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}\n",
        InstanceGuid.Data1, InstanceGuid.Data2, InstanceGuid.Data3,
        InstanceGuid.Data4[0], InstanceGuid.Data4[1], InstanceGuid.Data4[2], InstanceGuid.Data4[3],
        InstanceGuid.Data4[4], InstanceGuid.Data4[5], InstanceGuid.Data4[6], InstanceGuid.Data4[7]);

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_LGCLIENTDISPLAY, szWindowClass, MAX_LOADSTRING);

    if (!OnlyOneInstance())
    {
        std::cout << "Another Instance Running " << std::endl;
        return 1;
    }

    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance(hInstance, nCmdShow))
    {
        WSACleanup();
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_LGCLIENTDISPLAY));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    if (pCout)
    {
        fclose(pCout);
        FreeConsole();
    }
    WSACleanup();
    return (int)msg.wParam;
}

static int CountDups(char* string)
{
    int count = 0;
    size_t length = strlen(string);
    for (int i = 0; i < length; i++) {
        for (int j = i + 1; j < length; j++) {
            if (string[i] == string[j]) {
                count++;
                break;  // Exit the inner loop once a repeating digit is found
            }

        }
    }
    return count;
}

static void SetStdOutToNewConsole(void)
{
    // Allocate a console for this app
    AllocConsole();
    //AttachConsole(ATTACH_PARENT_PROCESS);
    freopen_s(&pCout, "CONOUT$", "w", stdout);
}

//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
static ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_LGCLIENTDISPLAY));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_LGCLIENTDISPLAY);
    wcex.lpszClassName = szWindowClass;
    wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
static BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    hInst = hInstance; // Store instance handle in our global variable

    HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

    if (!hWnd)
    {
        return FALSE;
    }

    //ShowWindow(hWnd, nCmdShow);
    ShowWindow(hWnd, SW_MAXIMIZE);
    UpdateWindow(hWnd);

    return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//


static LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_LBUTTONDOWN:
    {
        static int count = 0;
        PRINT(_T("click %d\r\n"), count++);
        SetFocus(hWnd);
    }
    break;
    case WM_KEYDOWN:
    {
        unsigned char SendCode = 0;
        BOOL calib = IsDlgButtonChecked(hWnd, IDC_CHECKBOX_CALIBRATE);
        if (calib)
        {
            if ((wParam == 'j') || (wParam == 'J')) SendCode = DEC_X;
            else if ((wParam == 'l') || (wParam == 'L')) SendCode = INC_X;
            else if ((wParam == 'i') || (wParam == 'I')) SendCode = INC_Y;
            else if ((wParam == 'm') || (wParam == 'M')) SendCode = DEC_Y;
            if (SendCode != 0)
            {
                SendCalibToSever(SendCode);
            }
        }
        else
        {
            if ((wParam == 'j') || (wParam == 'J')) SendCode = PAN_LEFT_START;
            else if ((wParam == 'l') || (wParam == 'L')) SendCode = PAN_RIGHT_START;
            else if ((wParam == 'i') || (wParam == 'I')) SendCode = PAN_UP_START;
            else if ((wParam == 'm') || (wParam == 'M')) SendCode = PAN_DOWN_START;
            else if ((wParam == 'f') || (wParam == 'F')) SendCode = FIRE_START;
            //MessageBeep(MB_ICONEXCLAMATION);
            if (SendCode != 0)
            {
                SendCodeToSever(SendCode);
            }
        }
    }
    break;
    case WM_KEYUP:
    {
        unsigned char SendCode = 0;
        if ((wParam == 'j') || (wParam == 'J')) SendCode = PAN_LEFT_STOP;
        else if ((wParam == 'l') || (wParam == 'L')) SendCode = PAN_RIGHT_STOP;
        else if ((wParam == 'i') || (wParam == 'I')) SendCode = PAN_UP_STOP;
        else if ((wParam == 'm') || (wParam == 'M')) SendCode = PAN_DOWN_STOP;
        else if ((wParam == 'f') || (wParam == 'F')) SendCode = FIRE_STOP;

        if (SendCode != 0)
        {
            SendCodeToSever(SendCode);
        }
    }
    break;
    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        // Parse the menu selections:
        switch (wmId)
        {
        case IDC_EDIT_REMOTE:
        {
            HWND hEditWnd;
            hEditWnd = GetDlgItem(hWnd, IDC_EDIT_REMOTE);
            GetWindowTextA(hEditWnd, RemoteAddress, sizeof(RemoteAddress));
            //PRINT(_T("IDC_EDIT_REMOTE\r\n"));
        }
        break;
        case IDC_EDIT_ENGAGE_ORDER:
        {
            HWND hEditWnd;
            char temp[512];

            hEditWnd = GetDlgItem(hWnd, IDC_EDIT_ENGAGE_ORDER);
            GetWindowTextA(hEditWnd, temp, sizeof(temp));
            if (CountDups(temp))
            {
                SetWindowTextA(hEditWnd, EngagementOrder);
                MessageBeep(MB_ICONEXCLAMATION);
            }
            else GetWindowTextA(hEditWnd, EngagementOrder, sizeof(EngagementOrder));
            //PRINT(_T("IDC_EDIT_ENGAGE_ORDER\r\n"));
        }
        break;
        case IDC_EDIT_PREARM_CODE:
        {
            HWND hEditWnd;
            char temp[512];

            hEditWnd = GetDlgItem(hWnd, IDC_EDIT_PREARM_CODE);
            GetWindowTextA(hEditWnd, temp, sizeof(temp));
            if (strlen(temp) > 8)
            {
                SetWindowTextA(hEditWnd, PreArmCode);
                MessageBeep(MB_ICONEXCLAMATION);
            }
            GetWindowTextA(hEditWnd, PreArmCode, sizeof(PreArmCode));
            //PRINT(_T("IDC_EDIT_ENGAGE_ORDER\r\n"));
        }
        break;

        case IDC_BUTTON_ADMIN_LOGIN:
            OnAdminLoginButtonClick(hWnd);
            break;

        case IDC_BUTTON_LOGIN:
        {
            // 로그인 버튼 클릭 처리
            OnLoginButtonClick(hWnd);
            break;
        }
        /*
        case IDC_BUTTON_LOGOUT:
        {
            // 로그아웃 버튼 클릭 처리
            OnLogout(hWnd);
            break;
        }
        */
        case IDC_BUTTON_REGISTER:
            OnRegistorButtonClick(hWnd);
            break;

        case IDC_BUTTON_CHANGE_PASSWORD:
            if (isLoggedIn) {
                DialogBox(hInst, MAKEINTRESOURCE(IDD_CHANGE_PASSWORD_DIALOG), hWnd, ChangePasswordDialogProc);
            }
            else {
                MessageBoxA(hWnd, "Please login first!", "Error", MB_OK | MB_ICONERROR);
            }
            break;

        case IDC_CHECKBOX_ARMED_MANUAL:
        {
            BOOL checked = IsDlgButtonChecked(hWnd, IDC_CHECKBOX_ARMED_MANUAL);
            if (checked) {
                SendStateChangeRequestToSever(PREARMED);

            }
            else {
                SendStateChangeRequestToSever(ARMED_MANUAL);
            }
        }
        break;


        case IDC_CHECKBOX_LASER_ENABLE:
        {
            BOOL checked = IsDlgButtonChecked(hWnd, IDC_CHECKBOX_LASER_ENABLE);
            if (checked) {
                CheckDlgButton(hWnd, IDC_CHECKBOX_LASER_ENABLE, BST_UNCHECKED);
                SystemState = (SystemState_t)(SystemState & CLEAR_LASER_MASK);
                SendStateChangeRequestToSever(SystemState);

            }
            else {
                CheckDlgButton(hWnd, IDC_CHECKBOX_LASER_ENABLE, BST_CHECKED);
                SystemState = (SystemState_t)(SystemState | LASER_ON);
                SendStateChangeRequestToSever(SystemState);

            }
        }
        break;
        //CAMERA CheckBox Enable 
        case IDC_CHECKBOX_CAMERA_ENABLE:
        {
            BOOL checked = IsDlgButtonChecked(hWnd, IDC_CHECKBOX_CAMERA_ENABLE);
            if (checked) {
                CheckDlgButton(hWnd, IDC_CHECKBOX_CAMERA_ENABLE, BST_UNCHECKED);
                SystemState = (SystemState_t)(SystemState & CLEAR_CAMERA_MASK);
                SendStateChangeRequestToSever(SystemState);
            }
            else {
                CheckDlgButton(hWnd, IDC_CHECKBOX_CAMERA_ENABLE, BST_CHECKED);
                SystemState = (SystemState_t)(SystemState | CAMERA_ON);
                SendStateChangeRequestToSever(SystemState);
            }
        }
        break;
        case IDC_CHECKBOX_AUTO_ENGAGE:
        {
            BOOL checked = IsDlgButtonChecked(hWnd, IDC_CHECKBOX_AUTO_ENGAGE);
            if (checked) {
                SendStateChangeRequestToSever(PREARMED);
            }
            else {
                SendTargetOrderToSever(EngagementOrder);
                SendStateChangeRequestToSever(ENGAGE_AUTO);
            }
        }
        break;
        case IDC_CHECKBOX_CALIBRATE:
        {
            BOOL checked = IsDlgButtonChecked(hWnd, IDC_CHECKBOX_CALIBRATE);
            if (checked) {
                SystemState = (SystemState_t)(SystemState & CLEAR_CALIB_MASK);
                SendStateChangeRequestToSever(SystemState);

            }
            else {
                CheckDlgButton(hWnd, IDC_CHECKBOX_CALIBRATE, BST_CHECKED);
                SystemState = (SystemState_t)(SystemState | CALIB_ON);
                SendStateChangeRequestToSever(SystemState);

            }
        }
        break;
        case IDC_BUTTON_PREARM_SAFE:
        {
            if ((SystemState & CLEAR_LASER_FIRING_ARMED_CALIB_MASK) == SAFE)
            {
                HWND hEditWnd;

                SendPreArmCodeToSever(PreArmCode);
                memset(PreArmCode, 0, sizeof(PreArmCode));
                hEditWnd = GetDlgItem(hWnd, IDC_EDIT_PREARM_CODE);
                SetWindowTextA(hEditWnd, PreArmCode);
            }
            else
            {
                SendStateChangeRequestToSever(SAFE);
            }
        }
        break;
        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            break;
        case IDM_EXIT:
            DestroyWindow(hWnd);
            break;
        case IDM_CONNECT:
            if (OnConnect(hWnd, message, wParam, lParam))
            {
                SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_CONNECT,
                    (LPARAM)MAKELONG(TBSTATE_INDETERMINATE, 0));
                SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_DISCONNECT,
                    (LPARAM)MAKELONG(TBSTATE_ENABLED, 0));
            }
            break;
        case IDM_DISCONNECT:
            SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_CONNECT,
                (LPARAM)MAKELONG(TBSTATE_ENABLED, 0));
            SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_DISCONNECT,
                (LPARAM)MAKELONG(TBSTATE_INDETERMINATE, 0));
            OnDisconnect(hWnd, message, wParam, lParam);
            break;

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
    }
    break;


    case WM_LOGIN_STATE:
    {
        /*
        TMesssageLoginVerifyResponse* MsgLoginVerifyRes;
        LogInState_t loginState = static_cast<LogInState_t>(wParam);
        MsgLoginVerifyRes = (TMesssageLoginVerifyResponse*)lParam;
        MsgLoginVerifyRes->LoginState = (LogInState_t)ntohl(MsgLoginVerifyRes->LoginState);
        unsigned int failCount = ntohl(MsgLoginVerifyRes->FailCount);

        std::string userID = loggedInUserID; // 로그인 시도한 사용자 ID
        */
        LogInState_t loginState = static_cast<LogInState_t>(wParam);

        if (loginState == SUCCESS) {
            DisplayMessageOkBox("Login Success!");
            //if (ntohl(MsgLoginVerifyRes->Privilige) == 1) {
            //    DisplayMessageOkBox("Admin으로 로그인 되었습니다.");
            //}
            //ShowLoggedInID(hWnd, userID.c_str()); // 로그인된 사용자 ID 표시
        }
        else if (loginState == NOT_EXIST_USER) {
            DisplayMessageOkBox("계정을 찾을 수 없습니다.");
        }
        else if (loginState == INVALID_PASSWORD) {
            DisplayMessageOkBox("비밀번호가 틀렸습니다.");
        }
        else if (loginState == AUTH_THROTTLED) {
            DisplayMessageOkBox("계정이 잠겼습니다. 1시간 후에 다시 시도하십시오.");
        }
        else {
            DisplayMessageOkBox("로그인 실패!");
        }
        break;
    }
    /*
    case MT_LOGIN_VERIFY_RES:
    {
        TMesssageLoginVerifyResponse* MsgLoginVerifyRes;
        MsgLoginVerifyRes = (TMesssageLoginVerifyResponse*)lParam;
        MsgLoginVerifyRes->LoginState = (LogInState_t)ntohl(MsgLoginVerifyRes->LoginState);
        unsigned int failCount = ntohl(MsgLoginVerifyRes->FailCount);

        std::string userID = loggedInUserID; // 로그인 시도한 사용자 ID

        if (MsgLoginVerifyRes->LoginState == INVALID_PASSWORD) {
                DisplayMessageOkBox("비밀번호가 틀렸습니다.");
        }
        else if (MsgLoginVerifyRes->LoginState == SUCCESS) {
            DisplayMessageOkBox("로그인 성공!");
            // Privilige 값 확인하여 admin 로그인 여부 표시
            if (ntohl(MsgLoginVerifyRes->Privilige) == 1) {
                DisplayMessageOkBox("Admin으로 로그인 되었습니다.");
            }
            ShowLoggedInID(hWnd, userID.c_str()); // 로그인된 사용자 ID 표시
        }
        else if (MsgLoginVerifyRes->LoginState == NOT_EXIST_USER) {
            DisplayMessageOkBox("계정을 찾을 수 없습니다.");
        }
        else if (MsgLoginVerifyRes->LoginState == AUTH_THROTTLED) {
            DisplayMessageOkBox("계정이 잠겼습니다. 1시간 후에 다시 시도하십시오.");
        }
        else {
            DisplayMessageOkBox("로그인 실패!");
        }

        break;
    }

    case MT_LOGIN_ENROLL_RES: {
        TMesssageLoginEnrollResponse* MsgLoginEnrolRes;
        MsgLoginEnrolRes = (TMesssageLoginEnrollResponse*)lParam;
        MsgLoginEnrolRes->LoginState = (LogInState_t)ntohl(MsgLoginEnrolRes->LoginState);

        if (MsgLoginEnrolRes->LoginState == INVALID_PASSWORD) {
              DisplayMessageOkBox("비밀번호가 틀렸습니다.");
         }
        else if (MsgLoginEnrolRes->LoginState == SUCCESS) {
               DisplayMessageOkBox("로그인 성공!");
        }
        else
        {
            ;;
        }
    }
    */
    case WM_CREATE:
        OnCreate(hWnd, message, wParam, lParam);
        break;
    case WM_SIZE:
        OnSize(hWnd, message, wParam, lParam);
        break;

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        // TODO: Add any drawing code that uses hdc here...
        //printf("paint\n");
        DisplayImage();
        EndPaint(hWnd, &ps);
    }
    break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    case WM_CLIENT_LOST:
        std::cout << "WM_CLIENT_LOST" << std::endl;
        SendMessage(hWndMain, WM_COMMAND, IDM_DISCONNECT, 0);
        break;
    case WM_REMOTE_CONNECT:
        SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_CONNECT,
            (LPARAM)MAKELONG(TBSTATE_INDETERMINATE, 0));
        break;
    case WM_REMOTE_LOST:
        SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_CONNECT,
            (LPARAM)MAKELONG(TBSTATE_ENABLED, 0));
        break;
    case WM_SYSTEM_STATE:
    {
        HWND hTempWnd;
        static bool LaserOn = false;
        hTempWnd = GetDlgItem(hWnd, IDC_SYSTEM_STATE);
        SystemState = (SystemState_t)wParam;

        if (SystemState & LASER_ON)
        {
            if ((SystemState & ENGAGE_AUTO) && (!LaserOn))
            {
                PlaySound(MAKEINTRESOURCE(PREFIRE_SOUND), NULL, SND_RESOURCE | SND_ASYNC);
            }
            CheckDlgButton(hWnd, IDC_CHECKBOX_LASER_ENABLE, BST_CHECKED);
            LaserOn = true;
        }
        else
        {
            CheckDlgButton(hWnd, IDC_CHECKBOX_LASER_ENABLE, BST_UNCHECKED);
            LaserOn = false;
        }

        if (SystemState & CALIB_ON)
            CheckDlgButton(hWnd, IDC_CHECKBOX_CALIBRATE, BST_CHECKED);
        else CheckDlgButton(hWnd, IDC_CHECKBOX_CALIBRATE, BST_UNCHECKED);

        switch (SystemState & CLEAR_LASER_FIRING_ARMED_CALIB_MASK)
        {
        case UNKNOWN:
            SetWindowTextA(hTempWnd, "Unknown");
            break;
        case SAFE:
            SetWindowTextA(hTempWnd, "Safe");
            SetWindowTextA(GetDlgItem(hWnd, IDC_BUTTON_PREARM_SAFE), "Pre-Arm Enable");
            EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_ARMED_MANUAL), false);
            EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_AUTO_ENGAGE), false);
            EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_LASER_ENABLE), false);
            EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_CALIBRATE), false);
            EnableWindow(GetDlgItem(hWnd, IDC_LABEL_ENGAGE_ORDER), false);
            EnableWindow(GetDlgItem(hWnd, IDC_EDIT_ENGAGE_ORDER), false);
            CheckDlgButton(hWnd, IDC_CHECKBOX_ARMED_MANUAL, BST_UNCHECKED);
            CheckDlgButton(hWnd, IDC_CHECKBOX_AUTO_ENGAGE, BST_UNCHECKED);
            CheckDlgButton(hWnd, IDC_CHECKBOX_LASER_ENABLE, BST_UNCHECKED);
            CheckDlgButton(hWnd, IDC_CHECKBOX_CALIBRATE, BST_UNCHECKED);
            EnableWindow(GetDlgItem(hWnd, IDC_LABEL_PREARM_CODE), true);
            EnableWindow(GetDlgItem(hWnd, IDC_EDIT_PREARM_CODE), true);
            break;
        case PREARMED:
            SetWindowTextA(hTempWnd, "Pre-Arm");
            SetWindowTextA(GetDlgItem(hWnd, IDC_BUTTON_PREARM_SAFE), "Safe");
            EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_ARMED_MANUAL), true);
            EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_AUTO_ENGAGE), true);
            EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_LASER_ENABLE), false);
            EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_CALIBRATE), false);
            EnableWindow(GetDlgItem(hWnd, IDC_LABEL_ENGAGE_ORDER), true);
            EnableWindow(GetDlgItem(hWnd, IDC_EDIT_ENGAGE_ORDER), true);
            CheckDlgButton(hWnd, IDC_CHECKBOX_ARMED_MANUAL, BST_UNCHECKED);
            CheckDlgButton(hWnd, IDC_CHECKBOX_LASER_ENABLE, BST_UNCHECKED);
            CheckDlgButton(hWnd, IDC_CHECKBOX_CALIBRATE, BST_UNCHECKED);
            CheckDlgButton(hWnd, IDC_CHECKBOX_AUTO_ENGAGE, BST_UNCHECKED);
            EnableWindow(GetDlgItem(hWnd, IDC_LABEL_PREARM_CODE), false);
            EnableWindow(GetDlgItem(hWnd, IDC_EDIT_PREARM_CODE), false);
            break;
        case ENGAGE_AUTO:
            if (SystemState & ARMED)
            {
                if (SystemState & FIRING)
                {
                    SetWindowTextA(hTempWnd, "Armed-FIRING");
                }
                else
                {
                    SetWindowTextA(hTempWnd, "Armed");
                }
            }
            else
            {
                if (SystemState & FIRING)
                {
                    SetWindowTextA(hTempWnd, "Engage Auto-FIRING");
                }
                else
                    SetWindowTextA(hTempWnd, "Engage Auto");
            }
            EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_ARMED_MANUAL), false);
            EnableWindow(GetDlgItem(hWnd, IDC_LABEL_ENGAGE_ORDER), false);
            EnableWindow(GetDlgItem(hWnd, IDC_EDIT_ENGAGE_ORDER), false);
            CheckDlgButton(hWnd, IDC_CHECKBOX_AUTO_ENGAGE, BST_CHECKED);
            break;
        case ARMED_MANUAL:
            if (SystemState & FIRING)
            {
                SetWindowTextA(hTempWnd, "Armed Manual- FIRING");
            }
            else SetWindowTextA(hTempWnd, "Armed Manual");
            EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_LASER_ENABLE), true);
            EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_CALIBRATE), true);
            CheckDlgButton(hWnd, IDC_CHECKBOX_ARMED_MANUAL, BST_CHECKED);
            EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_AUTO_ENGAGE), false);
            EnableWindow(GetDlgItem(hWnd, IDC_LABEL_ENGAGE_ORDER), false);
            EnableWindow(GetDlgItem(hWnd, IDC_EDIT_ENGAGE_ORDER), false);
            break;
        default:
            SetWindowTextA(hTempWnd, "Unknown Error");
            break;
        }
    }
    break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
static INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
HIMAGELIST g_hImageList = NULL;

HWND CreateSimpleToolbar(HWND hWndParent)
{
    // Declare and initialize local constants.
    const int ImageListID = 0;
    const int numButtons = 2;
    const int bitmapSize = 16;

    const DWORD buttonStyles = BTNS_AUTOSIZE;

    // Create the toolbar.
    HWND hWndToolbar = CreateWindowEx(0, TOOLBARCLASSNAME, NULL,
        WS_CHILD | TBSTYLE_WRAPABLE,
        0, 0, 0, 0,
        hWndParent, NULL, hInst, NULL);

    if (hWndToolbar == NULL)
        return NULL;

    // Create the image list.
    g_hImageList = ImageList_Create(bitmapSize, bitmapSize,   // Dimensions of individual bitmaps.
        ILC_COLOR16 | ILC_MASK,   // Ensures transparent background.
        numButtons, 0);

    // Set the image list.
    SendMessage(hWndToolbar, TB_SETIMAGELIST,
        (WPARAM)ImageListID,
        (LPARAM)g_hImageList);

    // Load the button images.
    SendMessage(hWndToolbar, TB_LOADIMAGES,
        (WPARAM)IDB_STD_SMALL_COLOR,
        (LPARAM)HINST_COMMCTRL);

    // Initialize button info.
    // IDM_NEW, IDM_OPEN, and IDM_SAVE are application-defined command constants.

    TBBUTTON tbButtons[numButtons] =
    {
        { MAKELONG(VIEW_NETCONNECT,    ImageListID), IDM_CONNECT,     TBSTATE_ENABLED,       buttonStyles, {0}, 0, (INT_PTR)L"Connect" },
        { MAKELONG(VIEW_NETDISCONNECT, ImageListID), IDM_DISCONNECT,  TBSTATE_INDETERMINATE, buttonStyles, {0}, 0, (INT_PTR)L"Disconnect"}
    };

    // Add buttons.
    SendMessage(hWndToolbar, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);
    SendMessage(hWndToolbar, TB_ADDBUTTONS, (WPARAM)numButtons, (LPARAM)&tbButtons);

    // Resize the toolbar, and then show it.
    SendMessage(hWndToolbar, TB_AUTOSIZE, 0, 0);
    ShowWindow(hWndToolbar, TRUE);

    return hWndToolbar;
}


static LRESULT OnCreate(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    UINT checked = BST_UNCHECKED;;
    InitCommonControls();

    CreateWindow(_T("STATIC"),
        _T("Logged in as:"),
        WS_VISIBLE | WS_CHILD,
        1100, 870, 100, 20,  // 초기 위치와 크기 (적절히 수정)
        hWnd,
        (HMENU)IDC_LABEL_LOGGEDIN_AS,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindow(_T("STATIC"),
        _T(""),
        WS_VISIBLE | WS_CHILD,
        1210, 870, 100, 20,
        hWnd,
        (HMENU)IDC_STATIC_LOGGEDIN_ID,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindow(_T("STATIC"),
        _T("Remote Address:"),
        WS_VISIBLE | WS_CHILD,
        5, 50, 120, 20,
        hWnd,
        (HMENU)IDC_LABEL_REMOTE,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindowExA(WS_EX_CLIENTEDGE,
        "EDIT", RemoteAddress,
        WS_CHILD | WS_VISIBLE,
        130, 50, 120, 20,
        hWnd,
        (HMENU)IDC_EDIT_REMOTE,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindow(_T("STATIC"),
        _T("Pre-Arm Code:"),
        WS_VISIBLE | WS_CHILD,
        260, 50, 95, 20,
        hWnd,
        (HMENU)IDC_LABEL_PREARM_CODE,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);
    EnableWindow(GetDlgItem(hWnd, IDC_LABEL_PREARM_CODE), false);

    HWND TmpHandle;
    TmpHandle = CreateWindowExA(WS_EX_CLIENTEDGE,
        "EDIT", PreArmCode,
        WS_CHILD | WS_VISIBLE,
        360, 50, 75, 20,
        hWnd,
        (HMENU)IDC_EDIT_PREARM_CODE,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);
    LONG style = GetWindowLong(TmpHandle, GWL_STYLE);
    SetWindowLong(TmpHandle, GWL_STYLE, style | ES_NUMBER);
    EnableWindow(GetDlgItem(hWnd, IDC_EDIT_PREARM_CODE), false);

    CreateWindow(_T("button"), _T("Pre-Arm Enable"),
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        445, 50, 105, 20,
        hWnd, (HMENU)IDC_BUTTON_PREARM_SAFE, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
    EnableWindow(GetDlgItem(hWnd, IDC_BUTTON_PREARM_SAFE), false);


    CreateWindow(_T("STATIC"),
        _T("System State:"),
        WS_VISIBLE | WS_CHILD,
        560, 50, 95, 20,
        hWnd,
        (HMENU)IDC_LABEL_SYSTEM_STATE,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindow(_T("STATIC"),
        _T("Unknown"),
        WS_VISIBLE | WS_CHILD,
        660, 50, 150, 20,
        hWnd,
        (HMENU)IDC_SYSTEM_STATE,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindow(_T("STATIC"),
        _T("ID:"),
        WS_VISIBLE | WS_CHILD,
        820, 50, 30, 20,
        hWnd,
        (HMENU)IDC_LABEL_ID,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindowExA(WS_EX_CLIENTEDGE,
        "EDIT", ID,
        WS_CHILD | WS_VISIBLE,
        860, 50, 120, 20,
        hWnd,
        (HMENU)IDC_EDIT_ID,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindow(_T("STATIC"),
        _T("Password:"),
        WS_VISIBLE | WS_CHILD,
        990, 50, 80, 20,
        hWnd,
        (HMENU)IDC_LABEL_PASSWORD,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindowExA(WS_EX_CLIENTEDGE,
        "EDIT", Password,
        WS_CHILD | WS_VISIBLE,
        1080, 50, 120, 20,
        hWnd,
        (HMENU)IDC_EDIT_PASSWORD,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindow(_T("button"), _T("Login"),
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        1210, 50, 60, 20,
        hWnd,
        (HMENU)IDC_BUTTON_LOGIN,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindow(_T("button"), _T("Change Password"),
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        1050, 75, 120, 20,  // ID 입력칸 아래로 이동
        hWnd,
        (HMENU)IDC_BUTTON_CHANGE_PASSWORD,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindow(_T("button"), _T("Register"),
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        1180, 75, 100, 20,  // ID 입력칸 아래로 이동
        hWnd,
        (HMENU)IDC_BUTTON_REGISTER,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindow(_T("button"), _T("Armed Manual"),
        WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
        5, 75, 115, 20,
        hWnd, (HMENU)IDC_CHECKBOX_ARMED_MANUAL, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
    CheckDlgButton(hWnd, IDC_CHECKBOX_ARMED_MANUAL, checked);
    EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_ARMED_MANUAL), false);

    CreateWindow(_T("button"), _T("Laser Enable"),
        WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
        130, 75, 110, 20,
        hWnd, (HMENU)IDC_CHECKBOX_LASER_ENABLE, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
    CheckDlgButton(hWnd, IDC_CHECKBOX_LASER_ENABLE, checked);
    EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_LASER_ENABLE), false);

    CreateWindow(_T("STATIC"),
        _T("Enage Order:"),
        WS_VISIBLE | WS_CHILD,
        250, 75, 90, 20,
        hWnd,
        (HMENU)IDC_LABEL_ENGAGE_ORDER,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);
    EnableWindow(GetDlgItem(hWnd, IDC_LABEL_ENGAGE_ORDER), false);

    TmpHandle = CreateWindowExA(WS_EX_CLIENTEDGE,
        "EDIT", EngagementOrder,
        WS_CHILD | WS_VISIBLE,
        350, 75, 90, 20,
        hWnd,
        (HMENU)IDC_EDIT_ENGAGE_ORDER,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);
    style = GetWindowLong(TmpHandle, GWL_STYLE);
    SetWindowLong(TmpHandle, GWL_STYLE, style | ES_NUMBER);
    EnableWindow(GetDlgItem(hWnd, IDC_EDIT_ENGAGE_ORDER), false);

    CreateWindow(_T("button"), _T("Auto Engage"),
        WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
        450, 75, 105, 20,
        hWnd, (HMENU)IDC_CHECKBOX_AUTO_ENGAGE, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
    CheckDlgButton(hWnd, IDC_CHECKBOX_AUTO_ENGAGE, checked);
    EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_AUTO_ENGAGE), false);

    CreateWindow(_T("button"), _T("Calibrate"),
        WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
        560, 75, 105, 20,
        hWnd, (HMENU)IDC_CHECKBOX_CALIBRATE, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
    CheckDlgButton(hWnd, IDC_CHECKBOX_CALIBRATE, checked);
    EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_CALIBRATE), false);

    CreateWindow(_T("button"), _T("Camera Enable"),
        WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
        670, 75, 130, 20,
        hWnd, (HMENU)IDC_CHECKBOX_CAMERA, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
    CheckDlgButton(hWnd, IDC_CHECKBOX_CAMERA, checked);
    EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_CAMERA), true);

    hWndEdit = CreateWindow(_T("edit"), NULL,
        WS_CHILD | WS_BORDER | WS_VISIBLE | ES_MULTILINE | WS_VSCROLL | ES_READONLY,
        0, 0, 0, 0, hWnd, (HMENU)IDC_EDIT, hInst, NULL);

    hWndMainToolbar = CreateSimpleToolbar(hWnd);

    hWndMain = hWnd;
    InitializeImageDisplay(hWndMain);
    PostMessage(hWndMain, WM_SYSTEM_STATE, UNKNOWN, 0);
    SetDisplayNoData();
    return 1;
}

LRESULT OnSize(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    int cxClient, cyClient;

    cxClient = LOWORD(lParam);
    cyClient = HIWORD(lParam);

    // Update the position of the ID display
    MoveWindow(GetDlgItem(hWnd, IDC_LABEL_LOGGEDIN_AS), cxClient - 200, cyClient - 50, 100, 20, TRUE);
    MoveWindow(GetDlgItem(hWnd, IDC_STATIC_LOGGEDIN_ID), cxClient - 100, cyClient - 50, 100, 20, TRUE);

    MoveWindow(hWndEdit, 5, cyClient - 70, cxClient - 10, 60, TRUE);

    return DefWindowProc(hWnd, message, wParam, lParam);

    return DefWindowProc(hWnd, message, wParam, lParam);
}

static int OnConnect(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    CStringW cstring(RemoteAddress);

    PRINT(_T("Remote Address : %s\r\n"), cstring);


    if (!IsClientConnected())
    {
        if (ConnectToSever(RemoteAddress, VIDEO_PORT))
        {
            std::cout << "Connected to Server" << std::endl;
            StartClient();
            std::cout << "Client Started.." << std::endl;
            EnableWindow(GetDlgItem(hWnd, IDC_BUTTON_PREARM_SAFE), true);
            EnableWindow(GetDlgItem(hWnd, IDC_EDIT_PREARM_CODE), true);
            EnableWindow(GetDlgItem(hWnd, IDC_LABEL_PREARM_CODE), true);
            return 1;
        }
        else
        {
            DisplayMessageOkBox("Connection Failed!");
            return 0;
        }

    }
    return 0;
}
static int OnDisconnect(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (IsClientConnected())
    {
        StopClient();
        PostMessage(hWndMain, WM_SYSTEM_STATE, UNKNOWN, 0);
        CheckDlgButton(hWnd, IDC_CHECKBOX_AUTO_ENGAGE, BST_UNCHECKED);
        CheckDlgButton(hWnd, IDC_CHECKBOX_LASER_ENABLE, BST_UNCHECKED);
        CheckDlgButton(hWnd, IDC_CHECKBOX_CALIBRATE, BST_UNCHECKED);
        CheckDlgButton(hWnd, IDC_CHECKBOX_ARMED_MANUAL, BST_UNCHECKED);
        EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_ARMED_MANUAL), FALSE);
        EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_LASER_ENABLE), FALSE);
        EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_CALIBRATE), FALSE);
        EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_AUTO_ENGAGE), FALSE);
        EnableWindow(GetDlgItem(hWnd, IDC_LABEL_ENGAGE_ORDER), FALSE);
        EnableWindow(GetDlgItem(hWnd, IDC_EDIT_ENGAGE_ORDER), FALSE);
        EnableWindow(GetDlgItem(hWnd, IDC_EDIT_PREARM_CODE), FALSE);
        EnableWindow(GetDlgItem(hWnd, IDC_LABEL_PREARM_CODE), FALSE);
        EnableWindow(GetDlgItem(hWnd, IDC_BUTTON_PREARM_SAFE), FALSE);
        SetDisplayNoData();
        std::cout << "Client Stopped" << std::endl;
    }
    return 1;
}
int PRINT(const TCHAR* fmt, ...)
{
    va_list argptr;
    TCHAR buffer[2048];
    int cnt;

    int iEditTextLength;
    HWND hWnd = hWndEdit;

    if (NULL == hWnd) return 0;

    va_start(argptr, fmt);

    cnt = wvsprintf(buffer, fmt, argptr);

    va_end(argptr);

    iEditTextLength = GetWindowTextLength(hWnd);
    if (iEditTextLength + cnt > 30000)       // edit text max length is 30000
    {
        SendMessage(hWnd, EM_SETSEL, 0, 10000);
        SendMessage(hWnd, WM_CLEAR, 0, 0);
        PostMessage(hWnd, EM_SETSEL, 0, 10000);
        iEditTextLength = iEditTextLength - 10000;
    }
    SendMessage(hWnd, EM_SETSEL, iEditTextLength, iEditTextLength);
    SendMessage(hWnd, EM_REPLACESEL, 0, (LPARAM)buffer);
    return(cnt);
}

/*
static void DisplayMessageOkBox(const char* Msg)
{
    int msgboxID = MessageBoxA(
        NULL,
        Msg,
        "Information",
        MB_OK | MB_TASKMODAL
    );

    switch (msgboxID)
    {
    case IDCANCEL:
        // TODO: add code
        break;
    case IDTRYAGAIN:
        // TODO: add code
        break;
    case IDCONTINUE:
        // TODO: add code
        break;
    }

}
*/
static bool OnlyOneInstance(void)
{
    HANDLE m_singleInstanceMutex = CreateMutex(NULL, TRUE, L"F2CBD5DE-2AEE-4BDA-8C56-D508CFD3F4DE");
    if (m_singleInstanceMutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS)
    {
        HWND existingApp = FindWindow(0, szTitle);
        if (existingApp)
        {
            ShowWindow(existingApp, SW_NORMAL);
            SetForegroundWindow(existingApp);
        }
        return false;
    }
    return true;
}

/*
bool IsAccountLocked(unsigned int failCount) {
    return failCount >= 3;
}

void RecordFailedAttempt(const std::string& userID) {
    auto it = accounts.find(userID);
    if (it != accounts.end()) {
        it->second.failedAttempts++;
        if (it->second.failedAttempts >= MAX_FAILED_ATTEMPTS) {
            it->second.lockTime = time(nullptr);
        }
    }
}

// 계정 잠금 시간 기록 함수
void RecordLockTime(const std::string& userID) {
    auto it = accounts.find(userID);
    if (it != accounts.end()) {
        it->second.lockTime = time(nullptr);
    }
}
*/

bool IsValidPassword(const std::string& password) {
    if (password.length() < 10) return false;
    bool hasLetter = false, hasDigit = false, hasSpecial = false;
    for (char c : password) {
        if (isalpha(c)) hasLetter = true;
        if (isdigit(c)) hasDigit = true;
        if (ispunct(c)) hasSpecial = true;
    }
    return hasLetter && hasDigit && hasSpecial;
}

INT_PTR CALLBACK ChangePasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            char currentPassword[32], newPassword[32], confirmPassword[32];
            GetDlgItemTextA(hDlg, IDC_EDIT_CURRENT_PASSWORD, currentPassword, sizeof(currentPassword));
            GetDlgItemTextA(hDlg, IDC_EDIT_NEW_PASSWORD, newPassword, sizeof(newPassword));
            GetDlgItemTextA(hDlg, IDC_EDIT_CONFIRM_PASSWORD, confirmPassword, sizeof(confirmPassword));

            if (strcmp(newPassword, confirmPassword) != 0) {
                MessageBoxA(hDlg, "New passwords do not match!", "Error", MB_OK | MB_ICONERROR);
                return (INT_PTR)FALSE;
            }

            if (!IsValidPassword(newPassword)) {
                MessageBoxA(hDlg, "New password must be at least 10 characters long and include at least one number and one special character.", "Error", MB_OK | MB_ICONERROR);
                return (INT_PTR)FALSE;
            }

            // Send password change request to server
            if (SendLoginChangePwToSever(currentUserId, newPassword)) {
                MessageBoxA(hDlg, "Password changed successfully!", "Success", MB_OK | MB_ICONINFORMATION);
                EndDialog(hDlg, LOWORD(wParam));
            }
            else {
                MessageBoxA(hDlg, "Failed to change password. Please try again.", "Error", MB_OK | MB_ICONERROR);
            }
        }
        else if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
        }
        break;
    }
    return (INT_PTR)FALSE;
}

// 관리자 로그인 다이얼로그 프로시저
INT_PTR CALLBACK AdminLoginDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    UNREFERENCED_PARAMETER(lParam);
    switch (message) {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            char adminId[32];
            char adminPw[32];

            GetWindowTextA(GetDlgItem(hDlg, IDC_EDIT_ADMIN_ID), adminId, sizeof(adminId));
            GetWindowTextA(GetDlgItem(hDlg, IDC_EDIT_ADMIN_PASSWORD), adminPw, sizeof(adminPw));

            if (SendLoginVerifyToSever(adminId, adminPw)) {
                MessageBox(hDlg, L"Admin Login Successful!", L"Success", MB_OK);
                ShowLoggedInID(hWndMain, adminId); // 로그인 ID 표시
                EndDialog(hDlg, LOWORD(wParam));
            }
            else {
                MessageBox(hDlg, L"Invalid Admin ID or Password", L"Error", MB_OK);
            }
        }
        else if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

void ShowLoggedInID(HWND hWnd, const char* id) {
    SetWindowTextA(GetDlgItem(hWnd, IDC_STATIC_LOGGEDIN_ID), id);
}

void OnAdminLoginButtonClick(HWND hWnd) {
    // 관리자 로그인 다이얼로그를 생성
    DialogBox(hInst, MAKEINTRESOURCE(IDD_ADMIN_LOGIN_DIALOG), hWnd, AdminLoginDialogProc);
}

void OnLoginButtonClick(HWND hWnd) {
    // Retrieve user input from the UI
    char userId[32];
    char userPw[32];
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_ID), userId, sizeof(userId));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PASSWORD), userPw, sizeof(userPw));

    // Validate input
    if (strlen(userId) == 0 || strlen(userPw) == 0) {
        DisplayMessageOkBox("ID나 Password를 입력하세요!");
        return;
    }

    std::string userID = userId;
    std::string password = userPw;

    loggedInUserID = userID; // 로그인 시도한 사용자 ID를 저장

    // Send login request to server
    if (SendLoginVerifyToSever(userId, userPw)) {
        std::cout << "Login request sent successfully" << std::endl;
    }
    else {
        std::cout << "Failed to send login request" << std::endl;
    }
}

void OnRegistorButtonClick(HWND hWnd) {
    // Retrieve user input from the UI
    char userId[32];
    char userPw[32];
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_ID), userId, sizeof(userId));
    GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT_PASSWORD), userPw, sizeof(userPw));

    // Validate input
    if (strlen(userId) == 0 || strlen(userPw) == 0) {
        DisplayMessageOkBox("Please enter your ID or password!");
        return;
    }

    std::string userID = userId;
    std::string password = userPw;

    // Check length of userId and userPw
    if (strlen(userId) >= sizeof(((TMesssageLoginVerifyRequest*)0)->Name) ||
        strlen(userPw) >= sizeof(((TMesssageLoginVerifyRequest*)0)->Password)) {
        DisplayMessageOkBox("ID or password is too long!");
        return;
    }

    // Send login request to server
    if (SendLoginEnrollToSever(userId, userPw)) {
        std::cout << "Enroll successfully" << std::endl;
    }
    else {
        std::cout << "Failed to Enroll request" << std::endl;
    }
}

void DisplayMessageOkBox(const char* Msg) {
    MessageBoxA(NULL, Msg, "Information", MB_OK | MB_TASKMODAL);
}
//-----------------------------------------------------------------
// END of File
//----------------------------------------------------------------- 
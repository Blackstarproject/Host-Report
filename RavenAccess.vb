Imports System.Runtime.InteropServices

Module RavenAccess
    'Impersonate as backup protocol against threats

#Region "Const"

    Public Const WINSTA_ALL_ACCESS As Integer = &H37F
    Public Const LOGON_NETCREDENTIALS_ONLY As Integer = &H1&
    Public Const CREATE_DEFAULT_ERROR_MODE As Integer = &H4000000
    Private Const CREATE_UNICODE_ENVIRONMENT As Integer = 1024

    'Constants for adjusting token privileges.

    Public Const ANYSIZE_ARRAY As Integer = 1

    Const TOKEN_QUERY As Integer = &H8
    Const TOKEN_DUPLICATE As Integer = &H2
    Const TOKEN_ASSIGN_PRIMARY As Integer = &H1
    Public Const TOKEN_ADJUST_PRIVILEGES As Integer = &H20

    Public Const SE_RESTORE_NAME As String = "SeRestorePrivilege"
    Public Const SE_BACKUP_NAME As String = "SeBackupPrivilege"
    Public Const SE_TCB_NAME As String = "SeTcbPrivilege"
    Public Const SE_ASSIGNPRIMARYTOKEN_NAME As String = "SeAssignPrimaryTokenPrivilege"
    Public Const SE_INCREASE_QUOTA_NAME As String = "SeIncreaseQuotaPrivilege"
    Public Const SE_PRIVILEGE_ENABLED As Integer = &H2

    'Process Startup
    Public Const SW_HIDE As Integer = 0

    Public Const SW_NORMAL As Integer = 1
    Public Const SW_SHOWMINIMIZED As Integer = 2
    Public Const SW_SHOWMAXIMIZED As Integer = 3
    Public Const SW_SHOWNOACTIVATE As Integer = 4
    Const SW_SHOW As Integer = 5
    Public Const SW_MINIMIZE As Integer = 6
    Public Const SW_SHOWMINNOACTIVE As Integer = 7
    Public Const SW_SHOWNA As Integer = 8
    Public Const SW_RESTORE As Integer = 9
    Public Const SW_SHOWDEFAULT As Integer = 10

    Const STARTF_FORCEONFEEDBACK As Integer = &H40
    Public Const STARTF_FORCEOFFFEEDBACK As Integer = &H80
    Public Const STARTF_PREVENTPINNING As Integer = &H2000
    Public Const STARTF_RUNFULLSCREEN As Integer = &H20
    Public Const STARTF_TITLEISAPPID As Integer = &H1000
    Public Const STARTF_TITLEISLINKNAME As Integer = &H800
    Public Const STARTF_USECOUNTCHARS As Integer = &H8
    Public Const STARTF_USEFILLATTRIBUTE As Integer = &H10
    Public Const STARTF_USEHOTKEY As Integer = &H200
    Public Const STARTF_USEPOSITION As Integer = &H4
    Public Const STARTF_USESHOWWINDOW As Integer = &H1
    Public Const STARTF_USESIZE As Integer = &H2
    Public Const STARTF_USESTDHANDLES As Integer = &H100

#End Region

#Region "Enums"

    Private Enum Logon32Type
        Interactive = 2
        Network = 3
        Batch = 4
        Service = 5
        Unlock = 7
        NetworkClearText = 8
        NewCredentials = 9
    End Enum

    Private Enum Logon32Provider
        [Default] = 0
        WinNT40 = 2
        WinNT50 = 3
    End Enum

    Public Enum NERR
        NERR_Success = 0
        NERR_InvalidComputer = 2351
        NERR_NotPrimary = 2226
        NERR_SpeGroupOp = 2234
        NERR_LastAdmin = 2452
        NERR_BadPassword = 2203
        NERR_PasswordTooShort = 2245
        NERR_UserNotFound = 2221
    End Enum

    Friend Enum SECURITY_IMPERSONATION_LEVEL
        SecurityAnonymous = 0
        SecurityIdentification = 1
        SecurityImpersonation = 2
        SecurityDelegation = 3
    End Enum

    Friend Enum TOKEN_TYPE
        TokenPrimary = 1
        TokenImpersonation = 2
    End Enum

#End Region

#Region "Structures"

    <StructLayout(LayoutKind.Sequential)>
    Public Structure PROCESS_INFORMATION
        Public hProcess As IntPtr
        Public hThread As IntPtr
        Public dwProcessId As UInteger
        Public dwThreadId As UInteger
    End Structure

    <StructLayout(LayoutKind.Sequential)>
    Public Structure SECURITY_ATTRIBUTES
        Public nLength As UInteger
        Public lpSecurityDescriptor As IntPtr
        Public bInheritHandle As Boolean
    End Structure

    <StructLayout(LayoutKind.Sequential)>
    Public Structure STARTUPINFO
        Public cb As UInteger
        Public lpReserved As String
        Public lpDesktop As String
        Public lpTitle As String
        Public dwX As UInteger
        Public dwY As UInteger
        Public dwXSize As UInteger
        Public dwYSize As UInteger
        Public dwXCountChars As UInteger
        Public dwYCountChars As UInteger
        Public dwFillAttribute As UInteger
        Public dwFlags As UInteger
        Public wShowWindow As Short
        Public cbReserved2 As Short
        Public lpReserved2 As IntPtr
        Public hStdInput As IntPtr
        Public hStdOutput As IntPtr
        Public hStdError As IntPtr
    End Structure

    Private Structure PROFILEINFO
        Public dwSize As Integer
        Public dwFlags As Integer
        Public lpUserName As String
        Public lpProfilePath As String
        Public lpDefaultPath As String
        Public lpServerName As String
        Public lpPolicyPath As String
        Public hProfile As IntPtr
    End Structure

    <StructLayout(LayoutKind.Sequential)> Public Structure USER_INFO_3
        <MarshalAs(UnmanagedType.LPWStr)> Public usri3_name As String
        <MarshalAs(UnmanagedType.LPWStr)> Public usri3_password As String
        Public usri3_password_age As Integer
        Public usri3_priv As Integer
        <MarshalAs(UnmanagedType.LPWStr)> Public usri3_home_dir As String
        <MarshalAs(UnmanagedType.LPWStr)> Public usri3_comment As String
        Public usri3_flags As Integer
        <MarshalAs(UnmanagedType.LPWStr)> Public usri3_script_path As String
        Public usri3_auth_flags As Integer
        <MarshalAs(UnmanagedType.LPWStr)> Public usri3_full_name As String
        <MarshalAs(UnmanagedType.LPWStr)> Public usri3_usr_comment As String
        <MarshalAs(UnmanagedType.LPWStr)> Public usri3_parms As String
        <MarshalAs(UnmanagedType.LPWStr)> Public usri3_workstations As String
        Public usri3_last_logon As Integer
        Public usri3_last_logoff As Integer
        Public usri3_acct_expires As Integer
        Public usri3_max_storage As Integer
        Public usri3_units_per_week As Integer
        <MarshalAs(UnmanagedType.U1)> Public usri3_logon_hours As Byte
        Public usri3_bad_pw_count As Integer
        Public usri3_num_logons As Integer
        <MarshalAs(UnmanagedType.LPWStr)> Public usri3_logon_server As String
        Public usri3_country_code As Integer
        Public usri3_code_page As Integer
        Public usri3_user_id As Integer
        Public usri3_primary_group_id As Integer
        <MarshalAs(UnmanagedType.LPWStr)> Public usri3_profile As String
        <MarshalAs(UnmanagedType.LPWStr)> Public usri3_home_dir_drive As String
        Public usri3_password_expired As Integer
    End Structure

    'Structures to adjust token privileges
    Public Structure LUID
        Public lowPart As UInteger
        Public highPart As Integer
    End Structure

    Public Structure LUID_AND_ATTRIBUTES
        Public luid As LUID
        Public attributes As UInteger
    End Structure

    Structure TOKEN_PRIVILEGES
        Public PrivilegeCount As Integer
        Public Privileges As LUID_AND_ATTRIBUTES

        Public Function Size() As Integer
            Return Marshal.SizeOf(Me)
        End Function

    End Structure

#End Region

#Region "API"

    Private Declare Auto Function LogonUserEx Lib "advapi32.dll" (lpszUsername As String, lpszDomain As String, lpszPassword As String, dwLogonType As Integer, dwLogonProvider As Integer, <Out()> ByRef hToken As IntPtr, pLogonSid As IntPtr, pProfileBuffer As IntPtr, pdwProfileLength As IntPtr, pQuotaLimits As IntPtr) As Integer
    Private Declare Auto Function ImpersonateLoggedOnUser Lib "advapi32" (hToken As IntPtr) As Integer
    Private Declare Auto Function CreateEnvironmentBlock Lib "userenv" (ByRef lpEnvironment As IntPtr, hToken As IntPtr, bInherit As Boolean) As Boolean
    Private Declare Auto Function GetUserProfileDirectory Lib "userenv" (hToken As IntPtr, lpProfileDir As String, ByRef lpcchSize As Integer) As Boolean
    Private Declare Ansi Function LoadUserProfile Lib "userenv" Alias "LoadUserProfileA" (hToken As IntPtr, ByRef lpProfileInfo As PROFILEINFO) As Boolean
    Private Declare Auto Function DestroyEnvironmentBlock Lib "userenv" (lpEnvironment As IntPtr) As Boolean
    Private Declare Auto Function UnloadUserProfile Lib "userenv" (hToken As IntPtr, hProfile As IntPtr) As Boolean
    Private Declare Auto Function RevertToSelf Lib "advapi32" () As Integer
    Private Declare Auto Function CloseHandle Lib "kernel32" (hObject As IntPtr) As Integer
    Private Declare Unicode Function NetUserGetInfo Lib "netapi32" (<MarshalAs(UnmanagedType.LPWStr)> servername As String, <MarshalAs(UnmanagedType.LPWStr)> username As String, level As Integer, ByRef bufptr As IntPtr) As Integer
    Private Declare Function NetApiBufferFree Lib "netapi32" (Buffer As IntPtr) As Integer
    Private Declare Auto Function CreateProcessAsUser Lib "advapi32" (hToken As IntPtr, lpApplicationName As String, lpCommandLine As String, ByRef lpProcessAttributes As SECURITY_ATTRIBUTES, ByRef lpThreadAttributes As SECURITY_ATTRIBUTES, bInheritHandles As Boolean, dwCreationFlags As Integer, lpEnvironment As IntPtr, lpCurrentDirectory As String, ByRef lpStartupInfo As STARTUPINFO, ByRef lpProcessInformation As PROCESS_INFORMATION) As Boolean

    'API to adjust token privileges
    Declare Function LookupPrivilegeValueA Lib "advapi32.dll" (lpSystemName As String, lpName As String, ByRef lpLuid As LUID) As Boolean
    Declare Function AdjustTokenPrivileges Lib "advapi32.dll" (TokenHandle As IntPtr, DisableAllPrivileges As Boolean, ByRef NewState As TOKEN_PRIVILEGES, BufferLength As Integer, PreviousState As IntPtr, ReturnLength As IntPtr) As Boolean

    Declare Auto Function DuplicateTokenEx Lib "advapi32.dll" (ExistingTokenHandle As IntPtr, dwDesiredAccess As UInteger, ByRef lpThreadAttributes As SECURITY_ATTRIBUTES, ImpersonationLevel As Integer, TokenType As Integer, ByRef DuplicateTokenHandle As IntPtr) As Boolean
    Declare Function OpenProcessToken Lib "advapi32.dll" (ProcessHandle As IntPtr, DesiredAccess As Integer, ByRef TokenHandle As IntPtr) As Boolean

#End Region

    Public Sub CreateProcess(Username As String, Domain As String, Password As String, Executable As String)
        On Error Resume Next
        Dim p_token As IntPtr = IntPtr.Zero
        Dim p_env As IntPtr = IntPtr.Zero
        Dim UserProfile As New PROFILEINFO

        StartImpersonation(Username, Domain, Password, p_token, p_env, UserProfile)

        Dim DupedToken As IntPtr = IntPtr.Zero

        Dim sa As New SECURITY_ATTRIBUTES
        sa.nLength = Convert.ToUInt32(Marshal.SizeOf(sa))

        If DuplicateTokenEx(p_token, Convert.ToUInt32(TOKEN_ASSIGN_PRIMARY Or TOKEN_DUPLICATE Or TOKEN_QUERY), sa, SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, TOKEN_TYPE.TokenPrimary, DupedToken) = False Then
            Debug.Write("DuplicateTokenEx Failed: " & Marshal.GetLastWin32Error.ToString)
        End If

        If Not (DupedToken.Equals(IntPtr.Zero)) Then
            Dim pi As New PROCESS_INFORMATION
            Dim saProcess As New SECURITY_ATTRIBUTES
            Dim saThread As New SECURITY_ATTRIBUTES
            saProcess.nLength = Convert.ToUInt32(Marshal.SizeOf(saProcess))
            saProcess.bInheritHandle = True
            saThread.nLength = Convert.ToUInt32(Marshal.SizeOf(saThread))
            saThread.bInheritHandle = True
            Dim si As New STARTUPINFO
            si.cb = Convert.ToUInt32(Marshal.SizeOf(si))
            si.lpDesktop = "WinSta0\Default"
            si.dwFlags = Convert.ToUInt32(STARTF_USESHOWWINDOW Or STARTF_FORCEONFEEDBACK)
            si.wShowWindow = SW_SHOW
            If CreateProcessAsUser(DupedToken, Nothing, "cmd", saProcess, saThread, True, CREATE_UNICODE_ENVIRONMENT, p_env, Nothing, si, pi) = False Then
                Debug.Write("CreateProcessAsUser Failed: " & Marshal.GetLastWin32Error.ToString)
            End If
        End If

        StopImpersonation(p_env, p_token, UserProfile)
        Debug.Write("User impersonation complete")
    End Sub

    Private Sub StartImpersonation(username As String, domain As String, password As String, p_token As IntPtr, p_env As IntPtr, userProfile As PROFILEINFO)
        On Error Resume Next
    End Sub

    Private Sub StopImpersonation(p_env As IntPtr, p_token As IntPtr, userProfile As PROFILEINFO)
        On Error Resume Next
    End Sub

End Module

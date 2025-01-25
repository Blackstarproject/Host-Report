Imports System.Runtime.InteropServices

Module Impersonation

#Region "API Structures"
    <StructLayout(LayoutKind.Sequential)>
    Public Structure PROCESS_INFORMATION
        Dim hProcess As IntPtr
        Dim hThread As IntPtr
        Dim dwProcessId As Integer
        Dim dwThreadId As Integer
    End Structure

    <StructLayout(LayoutKind.Sequential)>
    Public Structure STARTUPINFO
        Dim cb As Integer
        Dim lpReserved As IntPtr
        Dim lpDesktop As IntPtr
        Dim lpTitle As IntPtr
        Dim dwX As Integer
        Dim dwY As Integer
        Dim dwXSize As Integer
        Dim dwYSize As Integer
        Dim dwXCountChars As Integer
        Dim dwYCountChars As Integer
        Dim dwFillAttribute As Integer
        Dim dwFlags As Integer
        Dim wShowWindow As Short
        Dim cbReserved2 As Short
        Dim lpReserved2 As IntPtr
        Dim hStdInput As IntPtr
        Dim hStdOutput As IntPtr
        Dim hStdError As IntPtr
    End Structure

#End Region
#Region "API Constants"
    Private Const NORMAL_PRIORITY_CLASS As Integer = &H20
    Private Const CREATE_DEFAULT_ERROR_MODE As Integer = &H4000000
    Private Const CREATE_NEW_CONSOLE As Integer = &H10
    Private Const CREATE_NEW_PROCESS_GROUP As Integer = &H200
    Private Const LOGON_WITH_PROFILE As Integer = &H1
#End Region

#Region "API Functions"
    Private Declare Unicode Function CreateProcessWithLogon Lib "Advapi32" Alias "CreateProcessWithLogonW" _
        (lpUsername As String,
          lpDomain As String,
          lpPassword As String,
          dwLogonFlags As Integer,
          lpApplicationName As String,
          lpCommandLine As String,
          dwCreationFlags As Integer,
          lpEnvironment As IntPtr,
          lpCurrentDirectory As IntPtr,
         ByRef lpStartupInfo As STARTUPINFO,
         ByRef lpProcessInfo As PROCESS_INFORMATION) As Integer

    Private Declare Function CloseHandle Lib "kernel32" (hObject As IntPtr) As Integer

#End Region

    Public Sub RunProgram(UserName As String, Password As String, Domain As String, Application As String, CommandLine As String)

        Dim siStartup As STARTUPINFO
        Dim piProcess As PROCESS_INFORMATION
        Dim intReturn As Integer

        If CommandLine Is Nothing OrElse CommandLine = "" Then CommandLine = String.Empty

        siStartup.cb = Marshal.SizeOf(siStartup)
        siStartup.dwFlags = 0

        intReturn = CreateProcessWithLogon(UserName, Domain, Password, LOGON_WITH_PROFILE, Application, CommandLine,
        NORMAL_PRIORITY_CLASS Or CREATE_DEFAULT_ERROR_MODE Or CREATE_NEW_CONSOLE Or CREATE_NEW_PROCESS_GROUP,
        IntPtr.Zero, IntPtr.Zero, siStartup, piProcess)

        If intReturn = 0 Then
            Throw New System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error())
        End If

        CloseHandle(piProcess.hProcess)
        CloseHandle(piProcess.hThread)

    End Sub

End Module

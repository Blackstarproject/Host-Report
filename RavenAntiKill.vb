Imports System.ComponentModel
Imports System.Runtime.InteropServices
Imports System.Security.AccessControl
Imports System.Security.Principal

Public Class RavenAntiKill
    'The "GetSecurityInfo" function retrieves a copy of the security descriptor for an object specified by a handle.
    'How to prevent users from killing your service or process...
    Public Shared Function Protect(hProcess As IntPtr)
        On Error Resume Next
        'GetSecurityInfo function:Retrieves a copy of the security descriptor for an object specified by a handle.
        'To read the owner, group, or DACL from the object's security descriptor, the calling process must have been
        'granted "READ_CONTROL" Access when the handle was opened. To get READ_CONTROL access, the caller must be the owner
        'of the object or the object's DACL must grant the access.
        Dim dacl = GetProcessSecurityDescriptor(hProcess)
        dacl.DiscretionaryAcl.InsertAce(0, New CommonAce(AceFlags.None, AceQualifier.AccessDenied, ProcessAccessRights.PROCESS_ALL_ACCESS, New SecurityIdentifier(WellKnownSidType.WorldSid, Nothing), False, Nothing))
        SetProcessSecurityDescriptor(hProcess, dacl)
    End Function

    <DllImport("advapi32.dll", SetLastError:=True)>
    Private Shared Function GetKernelObjectSecurity(Handle As IntPtr, securityInformation As Integer, <Out()> pSecurityDescriptor As Byte(), nLength As UInteger, ByRef lpnLengthNeeded As UInteger) As Boolean
    End Function

    <DllImport("advapi32.dll", SetLastError:=True)>
    Private Shared Function SetKernelObjectSecurity(Handle As IntPtr, securityInformation As Integer, <[In]()> pSecurityDescriptor As Byte()) As Boolean
    End Function

    Private Shared Function InlineAssignHelper(Of T)(ByRef target As T, value As T) As T
        target = value
        Return value
    End Function

    Public Shared Sub SetProcessSecurityDescriptor(processHandle As IntPtr, dacl As RawSecurityDescriptor)
        Const DACL_SECURITY_INFORMATION As Integer = &H4
        Dim rawsd As Byte() = New Byte(dacl.BinaryLength - 1) {}
        dacl.GetBinaryForm(rawsd, 0)
        If Not SetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, rawsd) Then
            Throw New Win32Exception()
        End If
    End Sub

    Public Shared Function GetProcessSecurityDescriptor(processHandle As IntPtr) As RawSecurityDescriptor
        Const DACL_SECURITY_INFORMATION As Integer = &H4
        Dim psd As Byte() = New Byte(-1) {}
        Dim bufSizeNeeded As UInteger
        GetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, psd, 0, bufSizeNeeded)
        If bufSizeNeeded < 0 OrElse bufSizeNeeded > Short.MaxValue Then
            Throw New Win32Exception()
        End If
        If Not GetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, InlineAssignHelper(psd, New Byte(bufSizeNeeded - 1) {}), bufSizeNeeded, bufSizeNeeded) Then
            Throw New Win32Exception()
        End If
        Return New RawSecurityDescriptor(psd, 0)
    End Function

    'All possible access rights for a process object.Windows Server 2003 | Windows XP Windows 10: The size of the PROCESS_ALL_ACCESS flag increased
    'on Windows Server 2008 and Windows Vista. If an application compiled for Windows Server 2008 and Windows Vista is run on
    'Windows Server 2003 or Windows XP, Windows 10, the PROCESS_ALL_ACCESS flag is too large and the function specifying this flag fails
    'with ERROR_ACCESS_DENIED. To avoid this problem, specify the minimum set of access rights required for the operation.
    'If PROCESS_ALL_ACCESS must be used, set _WIN32_WINNT to the minimum operating system targeted by your application
    '(for example, #define _WIN32_WINNT _WIN32_WINNT_WINXP). For more information, see Using the Windows Headers.
    <Flags()>
    Public Enum ProcessAccessRights
        SYNCHRONIZE = &H100000
        STANDARD_RIGHTS_REQUIRED = &HF0000
        PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED Or SYNCHRONIZE Or &HFFF)
    End Enum

End Class

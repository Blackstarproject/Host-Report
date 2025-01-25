Imports System.Runtime.ConstrainedExecution
Imports System.Runtime.InteropServices

Public Class RavenPrivilegeClassToken
    'Defines the privileges of the user account associated with the access token.
    <Flags>
    Friend Enum TokenAccessLevels
        AssignPrimary = &H1
        Duplicate = &H2
        Impersonate = &H4
        Query = &H8
        QuerySource = &H10
        AdjustPrivileges = &H20
        AdjustGroups = &H40
        AdjustDefault = &H80
        AdjustSessionId = &H100
        Read = &H20000 Or Query
        Write = &H20000 Or AdjustPrivileges Or AdjustGroups Or AdjustDefault
        AllAccess = &HF0000 Or AssignPrimary Or Duplicate Or Impersonate Or Query Or QuerySource Or AdjustPrivileges Or AdjustGroups Or AdjustDefault Or AdjustSessionId
        MaximumAllowed = &H2000000
    End Enum

    'The SECURITY_IMPERSONATION_LEVEL enumeration contains values that specify security impersonation levels.
    'Security impersonation levels govern the degree to which a server process can act on behalf of a client process.
    Friend Enum SecurityImpersonationLevel
        Anonymous = 0
        Identification = 1
        Impersonation = 2
        Delegation = 3
    End Enum

    'Returns an array containing the constants of this enum type, in the order they are declared.
    Friend Enum TokenType
        Primary = 1
        Impersonation = 2
    End Enum

    'Represents the native methods that are shared between assemblies.
    Friend NotInheritable Class NativeMethods
        Friend Const SE_PRIVILEGE_DISABLED As UInteger = &H0
        Friend Const SE_PRIVILEGE_ENABLED As UInteger = &H2

        'Describes a local identifier for an adapter.
        <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Unicode)>
        Friend Structure LUID
            Friend LowPart As UInteger
            Friend HighPart As UInteger
        End Structure

        'LUID_AND_ATTRIBUTES structure can represent an LUID whose attributes change frequently, such as when the LUID is used to represent
        'privileges in the PRIVILEGE_SET structure. Privileges are represented by LUIDs and have attributes indicating whether they are
        'currently enabled or disabled.
        <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Unicode)>
        Friend Structure LUID_AND_ATTRIBUTES
            Friend Luid As LUID
            Friend Attributes As UInteger
        End Structure

        'The TOKEN_PRIVILEGES structure contains information about a set of privileges for an access token.
        <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Unicode)>
        Friend Structure TOKEN_PRIVILEGE
            Friend PrivilegeCount As UInteger
            Friend Privilege As LUID_AND_ATTRIBUTES
        End Structure

        Friend Const ADVAPI32 As String = "advapi32.dll"
        Friend Const KERNEL32 As String = "kernel32.dll"
        Friend Const ERROR_SUCCESS As Integer = &H0
        Friend Const ERROR_ACCESS_DENIED As Integer = &H5
        Friend Const ERROR_NOT_ENOUGH_MEMORY As Integer = &H8
        Friend Const ERROR_NO_TOKEN As Integer = &H3F0
        Friend Const ERROR_NOT_ALL_ASSIGNED As Integer = &H514
        Friend Const ERROR_NO_SUCH_PRIVILEGE As Integer = &H521
        Friend Const ERROR_CANT_OPEN_ANONYMOUS As Integer = &H543

        'In general, CloseHandle invalidates the specified object handle, decrements the object's handle count, and performs object retention checks.
        'After the last handle to an object is closed, the object is removed from the system. For a summary of the creator functions for these objects,
        'see Kernel Objects.
        <DllImport(KERNEL32, SetLastError:=True)>
        <ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)>
        Friend Shared Function CloseHandle(handle As IntPtr) As Boolean
        End Function

        'The AdjustTokenPrivileges function enables or disables privileges in the specified access token.
        'Enabling or disabling privileges in an access token requires TOKEN_ADJUST_PRIVILEGES access.
        <DllImport(ADVAPI32, CharSet:=CharSet.Unicode, SetLastError:=True)>
        <ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)>
        Friend Shared Function AdjustTokenPrivileges(
        <[In]> TokenHandle As SafeTokenHandle,
        <[In]> DisableAllPrivileges As Boolean,
        <[In]> ByRef NewState As TOKEN_PRIVILEGE,
        <[In]> BufferLength As UInteger,
        <[In], Out> ByRef PreviousState As TOKEN_PRIVILEGE,
        <[In], Out> ByRef ReturnLength As UInteger) As Boolean
        End Function

        'A process should call the RevertToSelf function after finishing any impersonation begun by using the DdeImpersonateClient,
        'ImpersonateDdeClientWindow, ImpersonateLoggedOnUser, ImpersonateNamedPipeClient, ImpersonateSelf, ImpersonateAnonymousToken or
        'SetThreadToken function. An RPC server that used the RpcImpersonateClient Function To impersonate
        'a client must Call the RpcRevertToSelf Or RpcRevertToSelfEx
        'To End the impersonation.
        'If RevertToSelf fails, your application continues To run In the context Of the client, which Is Not appropriate.
        'You should shut down the process If RevertToSelf fails.
        <DllImport(ADVAPI32, CharSet:=CharSet.Auto, SetLastError:=True)>
        <ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)>
        Friend Shared Function RevertToSelf() As Boolean
        End Function

        'The LookupPrivilegeValue function supports only the privileges specified in the Defined Privileges section of Winnt.h.
        'For a list of values, see Privilege Constants.
        <DllImport(ADVAPI32, EntryPoint:="LookupPrivilegeValueW", CharSet:=CharSet.Auto, SetLastError:=True)>
        <ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)>
        Friend Shared Function LookupPrivilegeValue(
        <[In]> lpSystemName As String,
        <[In]> lpName As String,
        <[In], Out> ByRef Luid As LUID) As Boolean
        End Function

        'A pseudo handle is a special constant, currently (HANDLE)-1, that is interpreted as the current process handle.
        'For compatibility with future operating systems, it is best to call GetCurrentProcess instead of hard-coding this constant value.
        'The calling process can use a pseudo handle to specify its own process whenever a process handle is required.
        'Pseudo handles are not inherited by child processes.
        <DllImport(KERNEL32, CharSet:=CharSet.Auto, SetLastError:=True)>
        <ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)>
        Friend Shared Function GetCurrentProcess() As IntPtr
        End Function

        'A pseudo handle is a special constant that is interpreted as the current thread handle.
        'The calling thread can use this handle to specify itself whenever a thread handle is required.
        'Pseudo handles are not inherited by child processes.
        'This handle has the THREAD_ALL_ACCESS access right To the thread Object. For more information,
        'see Thread Security And Access Rights.
        <DllImport(KERNEL32, CharSet:=CharSet.Auto, SetLastError:=True)>
        <ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)>
        Friend Shared Function GetCurrentThread() As IntPtr
        End Function

        'Close the access token handle returned through the TokenHandle parameter by calling CloseHandle.
        <DllImport(ADVAPI32, CharSet:=CharSet.Unicode, SetLastError:=True)>
        <ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)>
        Friend Shared Function OpenProcessToken(
        <[In]> ProcessToken As IntPtr,
        <[In]> DesiredAccess As TokenAccessLevels,
        <[In], Out> ByRef TokenHandle As SafeTokenHandle) As Boolean
        End Function

        'Tokens with the anonymous impersonation level cannot be opened.
        <DllImport(ADVAPI32, CharSet:=CharSet.Unicode, SetLastError:=True)>
        <ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)>
        Friend Shared Function OpenThreadToken(
        <[In]> ThreadToken As IntPtr,
        <[In]> DesiredAccess As TokenAccessLevels,
        <[In]> OpenAsSelf As Boolean,
        <[In], Out> ByRef TokenHandle As SafeTokenHandle) As Boolean
        End Function

        'The DuplicateTokenEx function creates a new access token that duplicates an existing token.
        'This function can create either a primary token or an impersonation token.
        <DllImport(ADVAPI32, CharSet:=CharSet.Unicode, SetLastError:=True)>
        <ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)>
        Friend Shared Function DuplicateTokenEx(
        <[In]> ExistingToken As SafeTokenHandle,
        <[In]> DesiredAccess As TokenAccessLevels,
        <[In]> TokenAttributes As IntPtr,
        <[In]> ImpersonationLevel As SecurityImpersonationLevel,
        <[In]> TokenType As TokenType,
        <[In], Out> ByRef NewToken As SafeTokenHandle) As Boolean
        End Function

        'The SetThreadToken function assigns an impersonation token to a thread.
        'The function can also cause a thread to stop using an impersonation token.
        <DllImport(ADVAPI32, CharSet:=CharSet.Unicode, SetLastError:=True)>
        <ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)>
        Friend Shared Function SetThreadToken(<[In]> Thread As IntPtr, <[In]> Token As SafeTokenHandle) As Boolean
        End Function


    End Class
End Class
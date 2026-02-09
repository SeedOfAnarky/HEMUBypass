Option Explicit

Dim shellApp, fso, scriptDir, ps1, args

Set shellApp = CreateObject("Shell.Application")
Set fso = CreateObject("Scripting.FileSystemObject")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
ps1 = scriptDir & "\\SOA_Launcher.ps1"

args = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File """ & ps1 & """"

' "runas" triggers UAC elevation. Window style 0 keeps the PowerShell console hidden.
On Error Resume Next
shellApp.ShellExecute "powershell.exe", args, scriptDir, "runas", 0
If Err.Number <> 0 Then
    MsgBox "Administrator rights are required to run the launcher.", vbOKOnly + vbExclamation, "SOA Launcher"
End If

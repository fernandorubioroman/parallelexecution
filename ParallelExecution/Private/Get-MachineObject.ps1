function Get-MachineObject
{
    param
    (
        $MachineList
    )

    $machinesarray = New-Object System.Collections.ArrayList # ArrayList is faster
    $MachineList | Sort-Object -Unique | ForEach-Object -Process `
    {
        $shortname = ($_ -split "\.", 2)[0]
        $DomainName = ($_ -split "\.", 2)[1]
        $machine = $_
    
        $machineobj = New-Object psobject
        $machineobj | Add-Member -MemberType NoteProperty -Name shortname  -Value $shortname  -Force
        $machineobj | Add-Member -MemberType NoteProperty -Name Domain  -Value $DomainName -Force 
        $machineobj | Add-Member -MemberType NoteProperty -Name hostname  -Value $machine -Force
        [void] ($machinesArray.Add($machineobj))
    }

    return $machinesarray 
}

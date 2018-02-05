function Get-MachineObject
{
    param
    (
        $MachineList
    )

    $machinesarray = New-Object System.Collections.ArrayList # ArrayList is faster
    #Refactored for speed (using collection initializer and removing variables, thanks to Steve Renard)
    $MachineList | Sort-Object -Unique | ForEach-Object -Process `
    {
        $machineobj = [PSCustomObject]@{
            shortname  = ($_ -split "\.", 2)[0]
            Domain =  ($_ -split "\.", 2)[1]
            hostname    = $_
        }
        [void] ($machinesArray.Add($machineobj))
    }
    return $machinesarray 
}

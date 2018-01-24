function Start-ParallelExecution
{
    
    <#
.SYNOPSIS
    This script runs a list of commands or scripts stored in a csv and on all the indicated machines. It supports 
    multiple forests using a xml file that stores multiple credentials, it supports  copying a folder to 
    destination machines (to copy required modules or other files)
    Everything is parallelized for fast execution. The result of the execution of the commands is stored on a xml 
    for further analysis or can be redirected to a variable
    It uses Powershell remoting for remote execution and SMB for prerequisites copy

.EXAMPLE
-------------------------- EXAMPLE 1 --------------------------
Start-ParallelExecution -ComputerNameFile .\machines.txt -InputCommandFile .\commands.csv -OutputFile .\output.xml -verbose

Description

-----------
This command get the list of machines specified on the ComputerNameFile parameter, runs the commands specified in the InputCommandFile parameter and stores the results in the OutputFile parameter, it uses -verbose to get execution information

-----------
.EXAMPLE
-------------------------- EXAMPLE 2 --------------------------
Start-ParallelExecution -ComputerNameFile .\machines.txt -CredentialFile .\creds.xml -InputCommandFile .\commands.csv -OutputFile .\output.xml 

Description

-----------
This command get the list of machines specified on the ComputerNameFile parameter, runs the commands specified in the InputCommandFile parameter,  using stored credentials from previous executions and stores the results in the OutputFile parameter

-----------
.EXAMPLE
-------------------------- EXAMPLE 3 --------------------------
Start-ParallelExecution -ComputerNameFile .\machines.txt -CredentialFile .\creds.xml -InputCommandFile .\commands.csv -OutputFile .\output.xml -prerequisitesfolder .\prereq -ScriptFolder .\scripts

Description

-----------
This command get the list of machines specified on the ComputerNameFile parameter, copy the contents of the folder specified on the prerequisitesfolder parameter to all of them, runs in paralel the commands and scripts specified in the InputCommandFile parameter,  using stored credentials from previous executions and scripts stored in the folder specified on the ScriptFolder parameter and stores the results in the OutputFile parameter

-----------
.EXAMPLE
-------------------------- EXAMPLE 4 --------------------------
Start-ParallelExecution -ComputerName machine1.contoso.com,machine2.contoso.com -CredentialFile .\creds.xml -InputCommandFile .\commands.csv -OutputFile .\output.xml -prerequisitesfolder .\prereq -ScriptFolder .\scripts

Description

-----------
This command  get the list of machines specified on the ComputerName parameter copy the contents of the folder specified on the prerequisitesfolder parameter, runs the commands and scripts specified in the InputCommandFile parameter,  using stored credentials from previous executions and scripts stored in the folder specified on the ScriptFolder parameter and stores the results in the OutputFile parameter

-----------
.EXAMPLE
-------------------------- EXAMPLE 5 --------------------------
Get-ADDomainController -filter * | select -expandproperty hostname |  Start-ParallelExecution  -CredentialFile .\creds.xml -InputCommandFile .\commands.csv -OutputFile .\output.xml -ScriptFolder .\scripts

Description

-----------
This command  get the list of machines passed through the pipeline (in the example we get the list of all domain controllers in a domain and use that as input), runs the commands and scripts specified in the InputCommandFile parameter,  using stored credentials from previous executions and scripts stored in the folder specified on the ScriptFolder parameter and stores the results in the OutputFile parameter

-----------
.EXAMPLE
-------------------------- EXAMPLE 6 --------------------------
$results = Start-ParallelExecution  -CredentialFile .\creds.xml -ComputerName machine1.contoso.com,machine2.contoso.com -InputCommandFile .\commands.csv -ScriptFolder .\scripts 

Description

-----------
This command gets a list of machines from the machinelist parameter, runs the commands and scripts specified in the InputCommandFile parameter,  using stored credentials from previous executions and scripts stored in the folder specified on the ScriptFolder parameter and stores the results in the $results variable.

-----------


 .PARAMETER InputCommandFile
This is the input file (# separated) with  the commands or scripts to run on each machine, the format is as follows
 -------------------------- EXAMPLE CSV FILE --------------------------
propertyname#command#Script#Description
testcommand #get-help#false#this executes get-help in the destination machines
#####lines starting with "#" are ignored######
testscript#.\testscript.ps1#true#this executes testsript.ps1 in the destination machines
-----------

.PARAMETER OutputFile
this optional parameter is the output file in xml format with the results of the commands ran against all machines, it contains a hashtable of objects with one entry per machine, each entry contains one property per command/script executed with the result of the execution of that command

.PARAMETER TimeoutInSeconds
This parameter contains the timeout used for jobs (to finish jobs that are hung)

.PARAMETER ComputerNameFile
This parameter contains the file with the list of fqdn of machines to run against

.PARAMETER machineslist
This parameter contains the comma separated list of fqdn of machines to work against, can accept input from pipeline

.PARAMETER CredentialFile
This optional parameter contains a xml file with the saved credentials per domain, if specified and the file does not exist it will ask for credentials and create the creds file for later use, if not specified it will use local logged on user credentials

.PARAMETER prerequisitesfolder
This optional parameter contains the path to a folder to be copied to the same destination to all computers (to include modules and other prerequisites)

.PARAMETER ScriptFolder
This optional parameter contains the path to a folder that contains all scripts that will be called from the InputCommandFile file)

.PARAMETER Command
This optional parameter contains a single command to be executed in paralel against all machines instead of using a csv file

.PARAMETER Throttlecopy
This optional parameter defines the number of simultaneous copy operations if a prerequisites folder is specified
#>
    [CmdletBinding(DefaultParameterSetName = 'PipelineSingle')]          
    Param(
        [parameter(Mandatory = $True,
            ValueFromPipeline = $True,
            HelpMessage = "Enter the list of machines's fqdn.",
            ValueFromPipelineByPropertyName = $True,        
            ParameterSetName = 'PipelineSingle')]
        [parameter(Mandatory = $True,
            ValueFromPipeline = $True,
            HelpMessage = "Enter the list of machines's fqdn.",
            ValueFromPipelineByPropertyName = $True,        
            ParameterSetName = 'PipelineMulti')]
        [string[]]
        $ComputerName,

        [parameter(Mandatory = $true,
            HelpMessage = "Enter txt file with the lists of machines's fqdn.",
            ParameterSetName = 'ListSingle')]
        [Parameter(Mandatory = $true,
            HelpMessage = "Enter txt file with the lists of machines's fqdn.",
            ParameterSetName = 'ListMulti')]
        [string]
        $ComputerNameFile,

        [Parameter(Mandatory = $true, ParameterSetName = 'PipelineMulti')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ListMulti')]
        [string]
        $InputCommandFile,

        [parameter(HelpMessage = "Enter the path of an xml to output de results.")]
        [string]
        $OutputFile,
        
        [string]
        $CredentialFile,

        [int]
        $TimeoutInSeconds = "600",
        
        [string]        
        $PrerequisitesFolder = ".\prereq\",

        [string]
        $ScriptFolder = ".\scripts\",

        [Parameter(Mandatory = $true, ParameterSetName = 'ListSingle')]
        [Parameter(Mandatory = $true, ParameterSetName = 'PipelineSingle')]
        [string]
        $Command,

        [string]
        $Throttlecopy = "5"
    )
    #We use an advanced function so if machines are passed through the pipeline, an array is created and then executed in paralel against all of them
    BEGIN
    {
        $pipelinearray = @(); 
    }
    PROCESS
    {
        $pipelinearray += $_; 
    }
    END
    {    
        #This code fills the machinelist variable with what has passed (if so) through the pipeline
        if ($pipelinearray -ne $null)
        {
            $ComputerName = $pipelinearray
        }

        #initialize some objects that will be later on used
        $machines = @()
        $i = 0
        $generalhashtable = @{}

        #Check that all needed files exist and break if not

        if ($PSBoundParameters.ContainsKey('prerequisitesfolder'))
        {
            try
            {
                $sourcepath = get-item $PrerequisitesFolder -ErrorAction stop
            }
            catch
            {
                Write-Error "prerequisites folder not found, closing"
                return
            }
        }

        if ($PSBoundParameters.ContainsKey('scriptsfolder'))
        {
            try
            {
                get-item $ScriptFolder -ErrorAction stop | Out-Null
            }
            catch
            {
                Write-Error "scripts folder not found, closing"
                return
            }
        }

        #if the machinesfile parameter has been specified we load the file, if not we already have an array of machines in the machineslist variable
        if ($PSCmdlet.ParameterSetName -like 'List*')
        {
            try
            {
                $ComputerName = Get-Content -Path $ComputerNameFile -ErrorAction Stop
            }
            catch
            {
                Write-Error "machines file not found, closing"
                return
            }
        }

        #we generate the commands list from the csv or directly from the single command parmeter
        if ($PSCmdlet.ParameterSetName -like '*Multi')
        {
            try
            {
                #For commands file we cleans commented ones (start with # so property name is empty)
                $commands = Import-Csv $InputCommandFile -Delimiter "#" -ErrorAction Stop | Where-Object {$_.PropertyName -ne ""}
            }
            catch
            {
                Write-Error "commands file not found, closing"
                return
            }
        }
        
        if ($PSCmdlet.ParameterSetName -like '*Single')
        {
            $commands = @()
            $commands += New-Object -TypeName psobject -Property @{
                propertyname = 'results'
                command      = $command
                Script       = $false
            }
        }        

        #generates machines objects from the list, creates the domain list and get a valid credential per each one of the domains if cred file is  specified and not exist
        $machines = Get-MachineObject $ComputerName
        $domains = $machines | Select-Object -ExpandProperty Domain | Sort-Object -Unique
        if ($PSBoundParameters.ContainsKey('CredentialFile'))
        {
            try
            {
                Get-Item $CredentialFile -ErrorAction stop | Out-Null
                $Domcreds = Get-DomainCredential -path $CredentialFile
            }
            catch
            {
                $Domcreds = Get-DomainCredential -Domain $Domains -path $CredentialFile
            }
        }

        #Cleanup stale pssessions and jobs from previous executions
        Get-PSSession | Where-Object Name -like 'ParallelExecution*' | Remove-PSSession
        Get-Job -Name Parallel*| stop-job 
        get-job -Name Parallel* |Remove-Job

        #We iterate over the domains opening sessions in paralel for each domain (we can not further parelalize because of credentials#>
        if ($PSBoundParameters.ContainsKey('CredentialFile'))
        {
            foreach ($domain in $domains)
            {
                $machinesinthisdomain = $machines| Where-Object {$_.domain -eq $domain}  
                [array]$countinthisdomain = $machinesinthisdomain
                write-verbose "opening sessions against  $($countinthisdomain.Count) machine(s) in domain  $domain"
                $machinesinthisdomain.hostname | ForEach-Object {New-PSSession -ComputerName $_ -Name "ParallelExecutionTo-$_" -Credential $Domcreds[$Domain] -ThrottleLimit 25} | Out-Null
            }
        }
        #if we use current logged on user credentials we can crete sessions in one step for all machines
        else
        {
        
            write-verbose "opening sessions against  $($machines.Count) machine(s)"
            $machines.Hostname | ForEach-Object {New-PSSession -ComputerName $_ -Name "ParallelExecutionTo-$_"  -ThrottleLimit 25} | Out-Null
        
        }
        #Generates the hashtable using the hostname as key and adding the hostname, Domain, and opened session as properties.
        foreach ($machine in $Machines)
        {
            $sessions = Get-PSSession | Where-Object Name -like 'ParallelExecution*'
            $session = $null
            $session = $sessions | Where-Object {$_.ComputerName -eq $machine.Hostname}
            if ($session)
            {
                $resultsobj = New-Object psobject
                $resultsobj | Add-Member -MemberType NoteProperty -Name Hostname  -Value $machine.HostName -force
                $resultsobj | Add-Member -MemberType NoteProperty -Name DomainName  -Value $machine.Domain -force 
                $resultsobj | Add-Member -MemberType NoteProperty -Name Session  -Value $session -force 
                $generalhashtable.add($machine.hostname, $resultsobj)
            }
            else {write-error "unable to open a session against $($machine.HostName)"}
        }

        write-verbose "successfully opened a session against $($generalhashtable.keys.Count) hosts"

        #Copy the prerequesites to the destination machines
        if ($PSBoundParameters.ContainsKey('prerequisitesfolder'))
        { 
            write-verbose "copying files"
            $job = $generalhashtable.keys| ForEach-Object {
                while (@(Get-Job -Name 'ParallelExecution*' | Where-Object State -eq Running).Count -ge $Throttlecopy)
                {
                    $now = Get-Date
                    foreach ($job in @(Get-Job -Name 'ParallelExecution*' | Where-Object State -eq Running))
                    {
                        if ($now - $job.PSBeginTime -gt [TimeSpan]::Fromseconds($TimeoutInSeconds))
                        {
                            Stop-Job $job
                        }
                    }
                    Start-Sleep -sec 2
                }
                $machine = $_
                $generalobj = $($generalhashtable.$machine)
                $domain = $generalobj.domainname
                write-verbose "starting copy on $_"
                if ($PSBoundParameters.ContainsKey('CredentialFile'))
                {
                    Start-Job -Name "ParallelExecution$_" -ScriptBlock {
                        param ($cpn, $sourcepath, $PrerequisitesFolder, $Domcreds, $Domain)
                        $short = $cpn.split(".")[0] + (random(1..100))
                        New-PSDrive -Name $short -PSProvider filesystem -Root "\\$cpn\c$" -Credential $Domcreds[$Domain]
                        $destinationpath = $short + ":" + $sourcepath.PSParentPath.split("::")[3]
                        #for this to work no other SMB connection (even an explorer one) has to be opened to the destination machine, TODO:Remove machines we can not copy prereqs to
                        $copy = copy-Item -Recurse -Force -Path $PrerequisitesFolder -Destination $destinationpath -PassThru 
                        Remove-PSDrive -Name $short
                    } -ArgumentList $_, $sourcepath, $PrerequisitesFolder, $Domcreds, $domain
                }
                else
                {
                    Start-Job -Name "ParallelExecution$_" -ScriptBlock {
                        param ($cpn, $sourcepath, $PrerequisitesFolder, $Domcreds, $Domain)
                        $short = $cpn.split(".")[0] + (random(1..100))
                        New-PSDrive -Name $short -PSProvider filesystem -Root "\\$cpn\c$" 
                        $destinationpath = $short + ":" + $sourcepath.PSParentPath.split("::")[3]
                        #for this to work no other SMB connection (even an explorer one) has to be opened to the destination machine, TODO:Remove machines we can not copy prereqs to
                        $copy = copy-Item -Recurse -Force -Path $PrerequisitesFolder -Destination $destinationpath -PassThru 
                        Remove-PSDrive -Name $short
                        write-verbose "copy finished on $cpn"
                    } -ArgumentList $_, $sourcepath, $PrerequisitesFolder, $Domcreds, $domain
                }
            }
            [void] ($job | Wait-Job | Receive-Job)
        }
        #clean stale jobs
        Get-Job -Name "ParallelExecution*" | stop-job 
        Get-Job -Name "ParallelExecution*"| remove-job

        #for each command for each one of the machines...
        foreach ($commandInfo in $commands)
        {
            $commandstarted = get-date
            #Start the execution of the jobs depending if it is a command or script what we need to run
            if (-not [System.Convert]::ToBoolean($commandInfo.script))
            {    
                write-verbose "Processing the command  $($commandInfo.propertyname)"
                foreach ($machine in $generalhashtable.keys)
                {
                    $i++
                    #converts the command to scriptblock and runs the command as a job
                    $scriptblock = [scriptblock]::create($commandInfo.command)
                    Invoke-Command -Session  $generalhashtable.$machine.session -ScriptBlock $scriptblock  -JobName "ParallelInvoke$i" -AsJob  | Out-Null
                }
            }
            elseif ([System.Convert]::ToBoolean($commandInfo.script))
            {
                write-verbose "Processing the script  $($commandInfo.propertyname)" 
                foreach ($machine in $generalhashtable.Keys)
                {
                    $i++
                    $filepath = $null
                    if ($ScriptFolder[-1] -ne "\") {$ScriptFolder = $ScriptFolder + "\"}
                    $filepath = $ScriptFolder + $commandInfo.command
                    Invoke-Command -Session  $generalhashtable.$machine.session -FilePath  $filepath -JobName "ParallelInvoke$i" -AsJob  | Out-Null
                }
            }
            else
            {
                write-verbose "Command $($commandInfo.command) not executed because could not identify if command or script, value was $($commandInfo.script) please check commands file"
            }

            #We sleep for some time to let the jobs finish and increase the timer in each future loop pass
            [int]$sleeptimer = 5
            While ((Get-Job -Name ParallelInvoke*).count -gT 0)
            {
                Start-Sleep -Seconds $sleeptimer
                $sleeptimer = $sleeptimer * 1.5
                $jobs = Get-Job -Name ParallelInvoke*
                $now = Get-Date
                #We go over the list of jobs receiving results and deleting failed or hung jobs
                foreach ($job in $jobs)
                {
                    $location = $job.location
                    #on completed jobs, receive the result, store the results and remove the jobs
                    if ($job.State -eq "Completed")
                    {
                        $result = $null
                        $result = Receive-Job $job
                        #Here we put in the machine object a new property with the result of the job
                        $generalhashtable.$Location| Add-Member -MemberType NoteProperty -Name $commandInfo.propertyname  -Value $result -force
                        Remove-job $job
                    }
                    #handles hung jobs so that are removed after timeout
                    elseif ($now - (Get-Job -Id $job.id).PSBeginTime -gt [TimeSpan]::FromSeconds($TimeoutInSeconds))
                    {
                        $generalhashtable.$Location| Add-Member -MemberType NoteProperty -Name $commandInfo.propertyname  -Value "JOBFAILED" -force
                        stop-job $job
                        write-verbose "The command failed due to timeout in $($job.Location)" 
                        remove-Job $job
                    }
                    #handles failed jobs 
                    elseif ($job.State -eq "Failed")
                    {
                        $location = $job.location
                        $generalhashtable.$Location| Add-Member -MemberType NoteProperty -Name $commandInfo.propertyname  -Value  "JOBFAILED" -force
                        write-verbose  "The command failed to execute in $($job.Location)" 
                        remove-Job $Job
                    }
                }
    
                #writes how long this command has been executed and how long to timeout
                $date = get-date
                [int]$spanned = ($date - $commandstarted).TotalSeconds
                $left = $TimeoutInSeconds - $spanned
                $pending = (get-job -Name ParallelInvoke*).count
                write-verbose "$pending jobs pending completion, current command has been running for $spanned seconds, $left seconds left"
            }
        }

        #cleanup sessions
        write-verbose "cleaning sessions"
        Get-PSSession | Where-Object Name -like 'ParallelExecution*' | Remove-PSSession

        #removing session from atributes as it is useless for output
        foreach ($ght in $generalhashtable.GetEnumerator())
        {
            $val = $ght.Value
            $val.PsObject.Members.Remove('Session')
        }

        #exporting to xml or to output, it seems we have encountered a bug here that gives unexpected output when exporting to xml if verbose is on
        #https://github.com/PowerShell/PowerShell/issues/1522
        if ($PSBoundParameters.ContainsKey('OutputFile'))
        {
            try
            {
                write-verbose "Data exporting to xml file" 
                $generalhashtable | Export-Clixml -Path $OutputFile
            }
            catch
            {
                Write-error "unable to write to output xml file" 
                break
            }
        }
        else
        {
            return $generalhashtable
        }
    }
}

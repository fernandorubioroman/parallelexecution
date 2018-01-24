# Get public and private function definition files.
$importFolders = Get-ChildItem $PSScriptRoot -Include Types, Public, Private -Recurse -Directory -ErrorAction SilentlyContinue
$types = @()
$private = @()
$public = @()

Write-Verbose -Message "Importing from $($importFolders.Count) folders"
foreach ($folder in $importFolders)
{
    switch ( $folder.Name)
    {
        'Types'
        {
            $types += Get-ChildItem -Path $folder.FullName
        }
        'Public'
        {
            $public += Get-ChildItem -Path  $folder.FullName
        }
        'Private'
        {
            $private += Get-ChildItem -Path  $folder.FullName
        }
    }
}
# Types first
foreach ( $type in $types)
{
    . $type.FullName
}

# Dot source the files
foreach ($import in @($public + $private))
{
    Try
    {
        . $import.FullName
    }
    Catch
    {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

Export-ModuleMember -Function $public.Basename

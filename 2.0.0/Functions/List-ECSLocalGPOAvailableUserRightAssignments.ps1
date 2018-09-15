Function List-ECSLocalGPOAvailableUserRightAssignments
    {
    <#
    .SYNOPSIS
    This displays a list of all user right assignments that this module support.  

    .DESCRIPTION
    Get-ECSLocalGPOUserRightAssignment will retrieve Local Group Policy Object (GPO) user right assignments.
    This function is useful if you're looking to audit or backup your current user right assignments to a CSV.
    This function utilizes the Windows builtin SecEdit.exe to export the user rights list, and then this function
    parses the exported file. 

    .PARAMETER MergedPolicy
    This parameter merges and exports domain and local policy security settings.

    .EXAMPLE
    This example exports all non-merged user right assignments.
        Get-ECSLocalGPOUserRightAssignment

    .EXAMPLE
    This example exports all MERGED user right assignments.
        Get-ECSLocalGPOUserRightAssignment -MergedPolicy
    #>
    [CmdletBinding()]
    
    ##########################################################################################################
    #Dynamic Params

    $FunctionRootPath = $PSScriptRoot
    $PowershellModuleRootPath = $($FunctionRootPath).Replace("\Functions","")
    $UserRightMappingsCSV = $PowershellModuleRootPath + "\Dependent Files\UserRightsMapping.csv"
    
    #End Dynamic Parameters
    ##########################################################################################################

    ##########################################################################################################
    #In verbose mode, we'll output the running values

    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message "Running Values"
    Write-Verbose -Message "Function Root Path = $($FunctionRootPath)"
    Write-Verbose -Message "Powershell Module Root Path: $($PowershellModuleRootPath)"
    Write-Verbose -Message "User Right Mappings CSV Path: $($UserRightMappingsCSV)"
    Write-Verbose -Message "END Running Values"
    Write-Verbose -Message "##########################################################################################################"

    #End In verbose mode, we'll output the running values
    ##########################################################################################################

    ##########################################################################################################
    #Importing the User rights mapping CSV

    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message "Importing the User rights mapping CSV"
    
    Try
        {
        Import-Csv -Path $UserRightMappingsCSV -ErrorAction Stop
        }
    Catch
        {
        write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
        Throw "Failed to import the user rights mapping CSV, see above"
        }


    Write-Verbose -Message "END Importing the User rights mapping CSV"
    Write-Verbose -Message "##########################################################################################################"

    #End Importing the User rights mapping CSV
    ##########################################################################################################
    
    }
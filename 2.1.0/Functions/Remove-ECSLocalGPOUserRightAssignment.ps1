Function Remove-ECSLocalGPOUserRightAssignment
    {
    <#
    .SYNOPSIS
    Removes an identity from a Local Group Policy Object (GPO) user right assignments.
    .DESCRIPTION
    Remove-ECSLocalGPOUserRightAssignment will remove an identity to a Local Group Policy Object (GPO) user right assignments.
    This function is useful if you're looking to remove a user right assignments from your local GPO.
    This function utilizes the Windows builtin SecEdit.exe to export the user rights list, and then this function
    parses the exported file. 
    .PARAMETER Identity
    This parameter can be an array of identities. Local, Domain and SIDs are all vailed options.
    .EXAMPLE
    This example removes multiple users to the shutdown right. Both sids and local users.
        Remove-ECSLocalGPOUserRightAssignment -Identity @("PCName\LocalGroup","S-1-5-32-555","domain\exampleuser") -SeShutdownPrivilege
    #>
    [CmdletBinding()]
     Param
	    (
        [Parameter(Mandatory = $True,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage="Enter an identity in the format of an NTAccount, SamAccountName of SID"
            )]
        [ValidateNotNullorEmpty()]
        [Alias('SID','AccountName','UserPrincipalName','SAMAccountName','NTAccount')]
        $Identity,

        [Parameter(Mandatory=$true)]
        [Validatescript(
            {
            #Getting a list of valid parameter values
            $SeceditNameValidationSet = $null
            $AllSeceditNamesToValidate = Show-ECSLocalGPOAvailableUserRightAssignments | Select-object -ExpandProperty SecEditName | sort-object
            
            #Creating a single line string, so if we find an invalid parameter, we can tell the user all the correct values
            Foreach ($SeceditNameToValidate in $AllSeceditNamesToValidate)
                {
                $SeceditNameValidationSet += """$SeceditNameToValidate"""
                }
            $SeceditNameValidationSet = $SeceditNameValidationSet -replace ('""','","')

            #Finally we validate the parameter
			If ($SeceditNameValidationSet -like "*$_*") 
                {
                $true
                }
			else 
                {
                Throw "Incorrect value, please use one of the following $($SeceditNameValidationSet)"
                }
			}
            )]
        [String]$SecEditName

	    )

    Process
        {

        ##########################################################################################################
        #Dynamic Params

        $TempDirectory = Get-childitem -Path env: | Where-Object {$_.name -eq "temp"} | select-object -ExpandProperty value
        $CurrentDateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $ExportOfSecuritySettingsName = "secedit_userrightassignment_export.tmp"
        $ExportofSecuritySettingsNameAndPath = $TempDirectory + "\" + $CurrentDateTime + "_" + $ExportOfSecuritySettingsName
        $ImportOfSecuritySettingsName = "secedit_userrightassignment_Import.tmp"
        $ImportofSecuritySettingsNameAndPath = $TempDirectory + "\" + $CurrentDateTime + "_" + $ImportOfSecuritySettingsName

        $SecEditStdOutPutFullFileName = $TempDirectory + "\" + $CurrentDateTime + "_" + "SeceditStdOutput.txt"
        $SecEditErrOutPutFullFileName = $TempDirectory + "\" + $CurrentDateTime + "_" + "SeceditErrOutput.txt"
        $FunctionRootPath = $PSScriptRoot
        $PowershellModuleRootPath = $($FunctionRootPath).Replace("\Functions","")

        $SIDRegexPattern = "S-\d-\d-\d+"
    

        #End Dynamic Parameters
        ##########################################################################################################

        ##########################################################################################################
        #Arrays to store results

        $AllDesiredIdentities = New-Object System.Collections.ArrayList
        $AllIdentities = New-Object System.Collections.ArrayList
        $FinalIdentites = New-Object System.Collections.ArrayList

        #End Arrays to store results
        ##########################################################################################################
    
        ##########################################################################################################
        #In verbose mode, we'll output the running values

        Write-Verbose -Message "##########################################################################################################"
        Write-Verbose -Message "Running Values"

        Write-verbose -Message "Export / Import Directory: $($TempDirectory)"
        Write-verbose -Message "TimeStamp Used for export file name: $($CurrentDateTime)"
        Write-verbose -Message "Export of user right assignment file name: $($ExportofSecuritySettingsNameAndPath)"
        Write-verbose -Message "Import of user right assignment file name: $($ImportofSecuritySettingsNameAndPath)"
        Write-verbose -Message "Secedit Standard Output file name: $($SecEditStdOutPutFullFileName)"
        Write-verbose -Message "Secedit Error Output file name: $($SecEditErrOutPutFullFileName)"
        Write-Verbose -Message "Function Root Path = $($FunctionRootPath)"
        Write-Verbose -Message "Powershell Module Root Path: $($PowershellModuleRootPath)"
        Write-Verbose -Message "User Right Assignment Selected: $($SecEditName)"
    

        Write-Verbose -Message "END Running Values"
        Write-Verbose -Message "##########################################################################################################"

        #End In verbose mode, we'll output the running values
        ##########################################################################################################

        ##########################################################################################################
        #Let's start by confirming all of desired ID's to add are legit.
        
        Write-Verbose -Message "##########################################################################################################"
        Write-Verbose -Message "Verifying ID's"

        Try
            {
            Foreach ($ID in $Identity)
                {
                If ($ID -match $SIDRegexPattern)
                    {
                    Write-Verbose -Message "The ID $($ID) is a SID, attempting a SID to account name translation"
                    $SIDToAccount = Convert-ECSSIDToAccount -SID $ID -ErrorAction Stop
                    $AllDesiredIdentities.Add($SIDToAccount) | Out-Null
                    }
                Else
                    {
                    Write-Verbose -Message "The ID $($ID) is NOT a SID, attempting an account name to SID translation"
                    $AccountToSID = Convert-ECSAccountToSID  -AccountName $ID -ErrorAction Stop
                    $AllDesiredIdentities.Add($AccountToSID) | Out-Null
                    }
                }
            }
        Catch
            {
            $Exception = $_.Exception 
            Write-error "$($Exception.Message)" 
            Throw "We failed to translate at least one of the identities entered."
            }

        #End Let's start by confirming all of desired ID's to add are legit.
        ##########################################################################################################

        ##########################################################################################################
        #Let's get the current list of security rights

        Write-Verbose -Message "##########################################################################################################"
        Write-Verbose -Message "Getting current user rights assignments"
    
        Try
            {
            Write-Verbose "Attepting to get a current list of ID's that have access for the requested right"
            $AllCurrentSecurityRights = Get-ECSLocalGPOUserRightAssignment | Where-Object {$_.SecEditUserRightName -like $SecEditName}
            
            }
        Catch
            {
            $Exception = $_.Exception 
            Write-error "$($Exception.Message)" 
            Throw "We failed to get a current list of ID's."
            }
               
        #End Let's get the current list of security rights
        ##########################################################################################################

        ##########################################################################################################
        #Let's merge the SIDS and filter out redudancies

        Write-Verbose -Message "##########################################################################################################"
        Write-Verbose -Message "Merging current and desired ID's"
    
        Try
            {
            $AllIdentities = Compare-Object -ReferenceObject $AllDesiredIdentities.Sid -DifferenceObject $AllCurrentSecurityRights.SIDWithOutTheAsterix | Where-Object {$_.SideIndicator -eq "=>"} | Select-Object -ExpandProperty InputObject
            
            }
        Catch
            {
            $Exception = $_.Exception 
            Write-error "$($Exception.Message)" 
            Throw "We failed to get a current list of ID's."
            }

        Write-Verbose "We are importing the following SIDS"
        Foreach ($SID_ID in $AllIdentities)
            {
            Write-Verbose -Message "SID: $($SID_ID)"
            }
               

        #End Let's merge the SIDS and filter out redudancies
        ##########################################################################################################
        
        ##########################################################################################################
        #Format the SID arry as a single string so we can import it.

        Write-Verbose -Message "##########################################################################################################"
        Write-Verbose -Message "Formatting SID's for the import"
        
        If ($AllIdentities -ne $null)
            {
            $FinalIdentites = "$($SecEditName) = "
            Foreach ($SID_ID in $AllIdentities)
                {
                $FinalIdentites += "*$($SID_ID),"
                }
        
            #removing the trailing comma
            $FinalIdentites = $FinalIdentites -replace ",$",""
            Write-Verbose "Formatted String: $($FinalIdentites)"
            }
        Else
            {
            Write-Verbose "There are no SIDS to import!!!"
            }
        
        #End Format the SID arry as a single string so we can import it.
        ##########################################################################################################

        ##########################################################################################################
        #Complete the desired import

        Write-Verbose -Message "##########################################################################################################"
        
        If ($AllIdentities -ne $null)
            {
            Write-Verbose -Message "Executing import"
   $SeceditFile= @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$($FinalIdentites)
"@ 

            #Export new file
            $SeceditFile | Set-Content -Path $ImportofSecuritySettingsNameAndPath -Encoding Unicode -Force

            #Finally we'll attempt to import the setting
            $ImportLocalSecurity = Start-process -FilePath "secedit.exe" -ArgumentList "/configure /db ""secedit.sdb"" /cfg ""$ImportofSecuritySettingsNameAndPath"" /areas USER_RIGHTS " -Wait -NoNewWindow -PassThru -RedirectStandardOutput $($SecEditStdOutPutFullFileName) -RedirectStandardError $($SecEditErrOutPutFullFileName)  -ErrorAction Stop
            if ($ImportLocalSecurity.ExitCode -ne 0)
                {
                Throw "Exit code $($ImportLocalSecurity.ExitCode) was not 0"
                }
            }
        
        #End Complete the desired import
        ##########################################################################################################
        
        }


    }
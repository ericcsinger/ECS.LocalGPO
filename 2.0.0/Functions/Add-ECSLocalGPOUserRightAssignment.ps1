Function Add-ECSLocalGPOUserRightAssignment
    {
    <#
    .SYNOPSIS
    Adds an identity to a Local Group Policy Object (GPO) user right assignments.
    .DESCRIPTION
    Add-ECSLocalGPOUserRightAssignment will add and identity to a Local Group Policy Object (GPO) user right assignments.
    This function is useful if you're looking to add a user right assignments to your local GPO.
    This function utilizes the Windows builtin SecEdit.exe to export the user rights list, and then this function
    parses the exported file. 
    .PARAMETER Identity
    This parameter can be an array of identities. Local, Domain and SIDs are all vailed options.
    .EXAMPLE
    This example adds multiple users to the shutdown right. Both sids and local users.
        Add-ECSLocalGPOUserRightAssignment -Identity @("PCName\LocalGroup","S-1-5-32-555","domain\exampleuser") -SeShutdownPrivilege
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
        [String]$Identity,

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

    process 
        {
        
        Foreach ($ID in $Identity)
            {
            Try
                {
                If ($ID -match $SIDRegexPattern)
                    {
                    Write-Verbose -Message "The ID $($ID) is a SID, attempting a SID to account name translation"
                    $SIDToAccount = Convert-ECSSIDToAccount -SID $ID -ErrorAction Stop
                    $AllDesiredIdentities.Add($SIDToAccount) | Out-Null
                    }
                }
            Catch
                {
                $Exception = $_.Exception 
                Write-error "$($Exception.Message)" 
                Throw "We failed to translate at one of the identities entered."
                }
            Else
                {
                Try
                    {
                    Write-Verbose -Message "The ID $($ID) is NOT a SID, attempting an account name to SID translation"
                    $AccountToSID = Convert-ECSAccountToSID  -AccountName $ID -ErrorAction Stop
                    $AllDesiredIdentities.Add($AccountToSID) | Out-Null
                    }
                Catch
                    {
                    $Exception = $_.Exception 
                    Write-error "$($Exception.Message)" 
                    Throw "We failed to translate at one of the identities entered."
                    }
                }
            }
        $AllDesiredIdentities
        }
        

        
        }

    #End Let's start by confirming all of desired ID's to add are legit.
    ##########################################################################################################































<#

    
    ##########################################################################################################
    #Now let's parse the additional user right assignments

    Write-Verbose -Message " "
    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message "Now let's parse the additional user right assignments"
    Write-Verbose -Message " "

    Foreach ($ID in $Identity)
        {
        Write-Verbose -Message " "
        Write-Verbose -Message "################"
        Write-Verbose -Message "Working on ID $($ID)"
        Write-Verbose -Message " "

        Write-Verbose "Determining if this is a SID or friendly account name"
        If ($ID -match $SIDRegexPattern)
            {
            Write-verbose "ID $($ID) is a SID"

            #Formatting the SID so it will be ready for the secedit import
            $SIDWITHTheAsterix = "*" + $ID

            #Looking up the SIDs friendly name
            Try
                {
                $objSID = New-Object System.Security.Principal.SecurityIdentifier ($ID) 
                $FriendlyNameToSIDMapping = $objSID.Translate( [System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty value
                Write-Verbose "found the name, $($FriendlyNameToSIDMapping)"
                }
            Catch
                {
                $FriendlyNameToSIDMapping = "Lookup Failed, might be orphaned"
                Write-Verbose "couldn't find the name"
                }

            $NewIdentitiesResult = New-Object PSObject -Property @{
	            SecEditUserRightName = $($UserRightSeceditName)
	            SIDWithOutTheAsterix = $($ID)
                SIDWITHTheAsterix = $($SIDWITHTheAsterix)
	            Identity = $($FriendlyNameToSIDMapping)
                ExistingID = $false
                }
            $Shhh = $AllIdentitiesdResults.Add($NewIdentitiesResult)
            }
        Else
            {
            Write-verbose "ID $($ID) is NOT a SID"

            #Let's try converting it to a SID
            Try
                {
                $objUser = New-Object System.Security.Principal.NTAccount($ID) 
                $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty value
                }
            Catch
                {
                Throw "This ID $($ID) has no SID that I can find, it might be spelled incorrectly"
                }

            #Formatting the SID so it will be ready for the secedit import
            $SIDWITHTheAsterix = "*" + $strSID

            #Formatting the user name for consistency
            $objSID = New-Object System.Security.Principal.SecurityIdentifier ($strSID) 
            $FriendlyNameToSIDMapping = $objSID.Translate( [System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty value
            
            $NewIdentitiesResult = New-Object PSObject -Property @{
	            SecEditUserRightName = $($UserRightSeceditName)
	            SIDWithOutTheAsterix = $($strSID)
                SIDWITHTheAsterix = $($SIDWITHTheAsterix)
	            Identity = $($FriendlyNameToSIDMapping)
                ExistingID = $false
                }
            $Shhh = $AllIdentitiesdResults.Add($NewIdentitiesResult)
            
            }

        Write-Verbose -Message " "
        Write-Verbose -Message "END Working on ID $($ID)"
        Write-Verbose -Message "################"
        Write-Verbose -Message " "
        }
    
    Write-Verbose -Message " "
    Write-Verbose -Message "END Now let's parse the additional user right assignments"
    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message " "

    #END Now let's parse the additional user right assignments
    ##########################################################################################################
    
    ##########################################################################################################
    #Compare the current and new ID's to check for things like duplicates

    Write-Verbose -Message " "
    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message "Compare the current and new ID's to check for things like duplicates"

    #Grouping so we can see if there are duplicates
    $MergedResults = $AllIdentitiesdResults | Group-Object -Property SIDWithOutTheAsterix

    #Preparing duplicates anoucment
    $DuplicateEntries = $MergedResults | Where-Object {$_.count -gt 1} 
    $NonDuplicateEntries = $MergedResults | Where-Object {$_.count -eq 1} 

    #Echo'ing dupes
    If ($DuplicateEntries-ne $null)
        {
        Write-Verbose " "
        Write-Verbose "#####################"
        Write-Verbose "#Duplicate SIDS"
        Write-Verbose " "
        
        Foreach ($Duplicate in $DuplicateEntries)
            {
            Write-Verbose ($Duplicate| Select-Object -ExpandProperty name)
            }

        
        Write-Verbose " "
        Write-Verbose "#END Duplicate SIDS"
        Write-Verbose "#####################"
        Write-Verbose " "
        }

    

    Write-Verbose -Message "END Compare the current and new ID's to check for things like duplicates"
    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message " "

    #End Compare the current and new ID's to check for things like duplicates
    ##########################################################################################################
    
    ##########################################################################################################
    #Creating a formal list of SIDS to import

    Write-Verbose -Message " "
    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message "Creating a formal list of SIDS to import"

    Write-Verbose -Message " "
    Write-Verbose -Message "#####################"
    Write-Verbose -Message "Merging dupes"
    Write-Verbose -Message " "

    #Parsing duplicates first
    Foreach ($Duplicate in $DuplicateEntries)
        {
        $ExpandDupe = $Duplicate | Select-Object -ExpandProperty Group
        $ExistingExpandDupe = $ExpandDupe | Where-Object {$_.ExistingID -eq $true} | Select-Object -First 1
        $NewExpandDupe = $ExpandDupe | Where-Object {$_.ExistingID -eq $false} | Select-Object -First 1

        
        If ($ExistingExpandDupe -ne $null)
            {
            $IdentitiesResult = New-Object PSObject -Property @{
	            SecEditUserRightName = $($ExistingExpandDupe.SecEditUserRightName)
	            SIDWithOutTheAsterix = $($ExistingExpandDupe.SIDWithOutTheAsterix)
                SIDWITHTheAsterix = $($ExistingExpandDupe.SIDWITHTheAsterix)
	            Identity = $($ExistingExpandDupe.Identity)
                ExistingID = $ExistingExpandDupe.ExistingID
                Duplicate = $true
                }
            $FinalIdentites.Add($IdentitiesResult) | Out-Null
            }
        Else
            {
            $IdentitiesResult = New-Object PSObject -Property @{
	            SecEditUserRightName = $($NewExpandDupe.SecEditUserRightName)
	            SIDWithOutTheAsterix = $($NewExpandDupe.SIDWithOutTheAsterix)
                SIDWITHTheAsterix = $($NewExpandDupe.SIDWITHTheAsterix)
	            Identity = $($NewExpandDupe.Identity)
                ExistingID = $NewExpandDupe.ExistingID
                Duplicate = $true
                }
            $FinalIdentites.Add($IdentitiesResult) | Out-Null
            }

        }

    Write-Verbose -Message " "
    Write-Verbose -Message "END Merging dupes"
    Write-Verbose -Message "#####################"
    Write-Verbose -Message " "

    Write-Verbose -Message " "
    Write-Verbose -Message "#####################"
    Write-Verbose -Message "Merging non-dupes"
    Write-Verbose -Message " "

    Foreach ($NonDuplicateEntrie in $NonDuplicateEntries)
        {
        $ExpandNonDupe = $NonDuplicateEntrie| Select-Object -ExpandProperty Group
         
        $IdentitiesResult = New-Object PSObject -Property @{
	        SecEditUserRightName = $($ExpandNonDupe.SecEditUserRightName)
	        SIDWithOutTheAsterix = $($ExpandNonDupe.SIDWithOutTheAsterix)
            SIDWITHTheAsterix = $($ExpandNonDupe.SIDWITHTheAsterix)
	        Identity = $($ExpandNonDupe.Identity)
            ExistingID = $ExpandNonDupe.ExistingID
            Duplicate = $false
            }
        $FinalIdentites.Add($IdentitiesResult) | Out-Null
        }


    Write-Verbose -Message " "
    Write-Verbose -Message "END Merging non-dupes"
    Write-Verbose -Message "#####################"
    Write-Verbose -Message " "

    Write-Verbose -Message "END Creating a formal list of SIDS to import"
    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message " "

    #End Creating a formal list of SIDS to import
    ##########################################################################################################
    
    
    
    
    ##########################################################################################################
    #Formatting the string of SIDS to add

    Write-Verbose -Message " "
    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message "Formatting the string of SIDS to add"


    Write-Verbose -Message "we will be importing the following SIDS"
    Foreach ($FinalIdentity in $FinalIdentites)
        {
        Write-Verbose "$($FinalIdentity.SIDWithOutTheAsterix)"
        }

    
    $FinalIdentitesCount = $FinalIdentites | Measure-Object | Select-Object -ExpandProperty count
    $FinalIdentitesCounter = 1
    $FinalIdentitesSIDsString = $null
    
    Foreach ($FinalIdentity in $FinalIdentites)
        {
        If ($FinalIdentitesCount -eq $FinalIdentitesCounter)
            {
            $FinalIdentitesSIDsString += $($FinalIdentity.SIDWITHTheAsterix)
            
            }
        Else
            {
            $FormattedSidString = $($FinalIdentity.SIDWITHTheAsterix) + ","
            $FinalIdentitesSIDsString += $FormattedSidString
            }
        $FinalIdentitesCounter++
        }

    Write-Verbose "The SID string we'll be importing is as follows: $($FinalIdentitesSIDsString)"

    Write-Verbose -Message "END Formatting the string of SIDS to add"
    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message " "

    #END Formatting the string of SIDS to add
    ##########################################################################################################
    
    
    ##########################################################################################################
    #Formatting the secedit file to import

    Write-Verbose -Message " "
    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message "Formatting the secedit file to import"


   $SeceditFile= @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$($UserRightAssignment) = $($FinalIdentitesSIDsString)
"@

    Write-Verbose "The secedit file we'll be importing will looks like this"
    Write-Verbose " "
    Write-Verbose -Message $SeceditFile

    Write-Verbose -Message "END Formatting the secedit file to import"
    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message " "

    #END Formatting the secedit file to import
    ##########################################################################################################
    
    ##########################################################################################################
    #Importing your secedit changes

    Write-Verbose -Message " "
    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message "Importing your secedit changes"

    #Export new file
    $SeceditFile | Set-Content -Path $ImportofSecuritySettingsNameAndPath -Encoding Unicode -Force

    #Finally we'll attempt to import the setting
    $ImportLocalSecurity = Start-process -FilePath "secedit.exe" -ArgumentList "/configure /db ""secedit.sdb"" /cfg ""$ImportofSecuritySettingsNameAndPath"" /areas USER_RIGHTS " -Wait -NoNewWindow -PassThru -RedirectStandardOutput $($SecEditStdOutPutFullFileName) -RedirectStandardError $($SecEditErrOutPutFullFileName)  -ErrorAction Stop
    if ($ImportLocalSecurity.ExitCode -ne 0)
        {
        Throw "Exit code $($ImportLocalSecurity.ExitCode) was not 0"
        }
    

    Write-Verbose "All ID's imported"
    $FinalIdentites 
    
    Write-Verbose -Message "END Importing your secedit changes"
    Write-Verbose -Message "##########################################################################################################"
    Write-Verbose -Message " "

    #END Importing your secedit changes
    ##########################################################################################################
    
    
    
    #>

    
    




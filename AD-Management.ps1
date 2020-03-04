#requires -version 4
<#
.SYNOPSIS
  A script to conduct AD Management tasks
.DESCRIPTION
  This script is for the mangement of Active Directory. It is controlled through a CLI menu system.
.PARAMETER <Parameter_Name>
  None
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        1.0
  Author:         Acidcrash376
  Creation Date:  02/03/2020
  Purpose/Change: Initial script development
  Web:            https://github.com/acidcrash376
.EXAMPLE
  ./AD-Management.ps1
  
#>

#---------------------------------------------------------[Script Parameters]------------------------------------------------------

Param (
  #Script parameters go here
)

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = 'SilentlyContinue'

#Import Modules & Snap-ins

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Any Global Declarations go here
$message = Write-Host ' Press [Space] to continue '

#-----------------------------------------------------------[Functions]------------------------------------------------------------

<#
Function <FunctionName> {
  Param ()
  Begin {
    Write-Host '<description of what is going on>...'
  }
  Process {
    Try {
      <code goes here>
    }
    Catch {
      Write-Host -BackgroundColor Red "Error: $($_.Exception)"
      Break
    }
  }
  End {
    If ($?) {
      Write-Host 'Completed Successfully.'
      Write-Host ' '
    }
  }
}
#>


################
# Start-Script #
################
function Start-Script {
Param ()
Begin {
    Write-Host "Script starting"
    }
Process {
    Try {
        ###########
        #Variables#
        ###########

       Start-Options
        }
        Catch {
      Write-Host -BackgroundColor Red "Error: $($_.Exception)"
      Break
    }
  }
  End {
    If ($?) {
      Write-Host 'User Created Successfully.'
      Write-Host ' '
    }
  }
}

#################
# Create a User #
#################
function NewUser {
Param ()
Begin {
    Write-Host "Creating a new user..."
    }
Process {
    Try {
        ###########
        #Variables#
        ###########
        #Sets the variable for the FQDN
        $domain = $env:USERDNSDOMAIN
        #Sets the variable for the first 3 characters (eg cpt from cpt.test)
        #in a later version, I would like to have it extract the first portion regardless of how many characters it is.
        $domshort = $env:USERDNSDOMAIN.Substring(0,3)
        #Defines the domain DistinguishedName:- dc=domain,dc=com 
        $dn = Get-ADDomain | select -ExpandProperty DistinguishedName 
        #Prompts for User's first and second name, then combines for the Full Name and, at present, the Display name
        $givenname = Read-Host 'What is the users First Name?' 
        $surname = Read-Host 'What is the users Surname?'
        $fullname = $givenname + ' ' + $surname
        $displayname = $givenname + ' ' + $surname
        #Defines the logon name in the format of surname + first character of first name and a digit value. 
        #In a later version, I want it to check if the user already exists and increment the number
        $samname = $surname+$givenname.substring(0,1)+'100'
        #Defines the logon in UPN format with the FQDN appended to the end
        $upn = $samname + '@' + $domain.ToLower()
        #Defines the logon pre-pended by the domain as per user logon
        $logon = $domshort + '\' + $samname.ToLower()
        #Sets a default password, this could be made user definable if desired rather than a hard coded password.
        $rand = Get-Random -Maximum 9999 -Minimum 1000
        $plainpassword = 'Welcome=' + $rand   
        $SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force 
        #What OU would the user created in
        #$ou = Read-Host 'What OU is the user to be created in? Format: OU=X,OU=Y,OU=Z. Do not include the domain DN'
        $ou = 'OU=Users,OU=Accounts,OU=CPT'
        $oupath = $ou + ',' + $dn
        #Defines the User Distinguished Name
        
        ###########
        #Variables#
        ###########

        Write-Host ''        
        Write-Host ''
        Write-Host 'First Name:                ' -Foregroundcolor Yellow -nonewline; Write-Host $givenname -foregroundcolor Green
        Write-Host 'Surname:                   ' -ForegroundColor Yellow -NoNewline; Write-Host $surname -ForegroundColor Green
        Write-Host 'Full Name:                 '-Foregroundcolor Yellow -nonewline; Write-Host $fullname -ForegroundColor Green
        Write-Host 'UserPrincipleName:         '-Foregroundcolor Yellow -nonewline; Write-Host $upn -ForegroundColor Green
        Write-Host 'SAM Name:                  '-Foregroundcolor Yellow -nonewline; Write-Host $samname -ForegroundColor Green
        Write-Host 'Password:                  ' -Foregroundcolor Yellow -nonewline; Write-Host $PlainPassword -ForegroundColor Green
        #Write-Host 'The user must change their password on logon!' -ForegroundColor Magenta
        #Write-Host ''
        #Write-Host 'Logon:              ' -Foregroundcolor Yellow -nonewline; Write-Host $logon -ForegroundColor Green
        #Write-Host ''
        #Write-Host 'Organizational Unit:       ' -ForegroundColor Yellow -NoNewline; Write-Host $oupath -ForegroundColor Green
        #Write-Host ''
     
        New-ADUser -GivenName $givenname -Surname $surname -Name $fullname -DisplayName $displayname -SamAccountName $samname -UserPrincipalName $upn -ChangePasswordAtLogon:$true -AccountPassword $SecurePassword -Enabled:$true -Path $oupath
        #Write-Host ''
        $udn = Get-ADUser -Filter 'SamAccountName -eq $samname' | select -ExpandProperty DistinguishedName
        Write-Host 'User Distinguished Name:   ' -ForegroundColor Yellow -NoNewline; Write-Host $udn -ForegroundColor Green
        }
        Catch {
      Write-Host -BackgroundColor Red "Error: $($_.Exception)"
      Break
    }
  }
  End {
    If ($?) {
      Write-Host 'User Created Successfully.'
      Write-Host ' '
      Sleep 5
      Start-Options
    }
  }
}

###############################
# Generate a default password #
###############################
Function RandomDefaultPassword {
Param ()
Begin {
}
Process {
        Try {
            $rand = Get-Random -Maximum 999
            $password = 'Welcome=' + $rand
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'Random Password is:' $password
                      Write-Host ' '
                      Pause
                      Start-Options
                    }
        }
}

##############################
# Generate a strong password #
##############################
Function RandomSecurePassword {
Param ()
Begin {
}
Process {
        Try {
        ################
        # Still to do! #
        ################
            $rand = Get-Random -Maximum 999
            $password = 'Welcome=' + $rand
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'Random Complex Password is:' $password
                      Write-Host ' '
                      Start-Options
                    }
        }
}

###############################
# Search Organisational Units #
###############################
Function SearchOU {
Param ()
Begin {
}
Process {
        Try {
            ###########
            #Variables#
            ###########
            $ou = Read-Host 'What is the name of the OU?'
            $searchedou = '*'+$ou+'*'
            Get-ADOrganizationalUnit -Filter 'Name -like $searchedou' | select -ExpandProperty DistinguishedName
            Write-Host ''
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'Search complete'
                      Write-Host ' '
                    }
        }
}

###################
# Search User #
###################
Function Searchuser {
Param ()
Begin {
}
Process {
        Try {
            ###########
            #Variables#
            ###########
            $user = Read-Host 'What is the Name or Logon of the User?'
            $suser = '*'+$user+'*'
            get-aduser -filter "(name -like '$suser') -Or (SamAccountName -like '$suser')" | ft Name,DistinguishedName
            #Get-ADObject -Filter 'Name -like $searchedcomputer' | ft Name,DistinguishedName
            Write-Host ''
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'Search complete'
                      Write-Host ' '
                    }
        }
}

###################
# Search Computer #
###################
Function SearchComputer {
Param ()
Begin {
}
Process {
        Try {
            ###########
            #Variables#
            ###########
            $computer = Read-Host 'What is the name of the Computer?'
            $searchedcomputer = '*'+$computer+'*'
            Get-ADComputer -Filter 'ObjectClass -eq "Computer"' | Where-Object name -Like $searchedcomputer | ft Name,DistinguishedName
            #Get-ADObject -Filter 'Name -like $searchedcomputer' | ft Name,DistinguishedName
            Write-Host ''
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'Search complete'
                      Write-Host ' '
                    }
        }
}

###################################
# Set A Users Organisational Unit #
###################################
Function SetUserOU {
Param ()
Begin {
}
Process {
        Try {
            ###########
            #Variables#
            ###########
            $samname = Read-Host 'Enter the users logonname in SAM Account Format'
            $udn = Get-ADUser -Filter 'SamAccountName -eq $samname' | select -ExpandProperty DistinguishedName
            $targetou = Read-Host 'Enter the desired OU in Destinguished Name format (OU=A,DC=B,DC=C)'

            Move-ADObject -Identity $udn -TargetPath $targetou
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'User moved successfully'
                      Write-Host ' '
                    }
        }
}

#######################################
# Set A Computers Organisational Unit #
#######################################
Function SetComputerOU {
Param ()
Begin {
}
Process {
        Try {
            ###########
            #Variables#
            ###########
            $computername = Read-Host 'Enter the Name or partial name of the computer you want to move to a new OU'
            $udn = Get-ADUser -Filter 'SamAccountName -eq $samname' | select -ExpandProperty DistinguishedName
            $targetou = Read-Host 'Enter the desired OU in Destinguished Name format (OU=A,DC=B,DC=C)'

            Move-ADObject -Identity $udn -TargetPath $targetou
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'User moved successfully'
                      Write-Host ' '
                    }
        }
}

########################
# Set A Users password #
########################
Function SetUserPW {
Param (
        [String]$user = $(Write-Host 'Enter the logon for the user you want to set a password for: ' -foregroundcolor Yellow -NoNewLine; Read-Host),
        [String]$temppass = $(Write-Host 'Enter the desired temporary password: ' -Foregroundcolor Yellow; Read-Host -AsSecureString)
)
Begin {
}
Process {
        Try {
            ###########
            #Variables#
            ###########
            #Write-Host 'Enter the logon for the user you want to set a password for.' -f
            #$user = Read-Host "Enter the Logon for the user you want to set a password for"
            $udn = Get-ADUser -Filter 'SamAccountName -eq $samname' | select -ExpandProperty DistinguishedName
            #$temppass = Read-Host 'Enter the desired temporary password'

            Set-ADAccountPassword -Identity $udn -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $temppass -Force)
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'Password sucessfully changed for user'$user -ForegroundColor Green
                      Write-Host ' '
                    }
        }
}

############
# Menu GUI #
############
Function Start-Menu {
Param (
        [String]$userinput = $(Write-Host 'Select an Option: ' -foregroundcolor Yellow -NoNewLine; Read-Host)
)
Begin {
}
Process {
        Try {
            Switch ( $userinput )
                {
                0 { RandomDefaultPassword }
                1 { RandomSecurePassword }
                2 { Searchuser }
                3 { SearchComputer }
                4 { SearchOU }
                5 { NewUser }
                6 { SetUserOU }
                7 { SetComputerOU }
                8 { SetUserPW }
                9 { Exit }
                }
                Start-Menu
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'Password sucessfully changed for user'$user -ForegroundColor Green
                      Write-Host ' '
                    }
        }
}

################
# Menu Options #
################
Function Start-Options {
Param (

)
Begin {
}
Process {
        Try {
            Clear-Host
            Write-Host ' '
            Write-Host ' Active Directory Manamgenent Tasks '
            Write-Host ' ================================== '
            Write-Host ' '
            Write-Host ' '
            Write-Host ' Options: '
            Write-Host ' --------'
            Write-Host ' '
            Write-Host ' 0 - Generate a random Default Password '
            Write-Host ' 1 - Generate a random Secure Password '
            Write-Host ' 2 - Search for a user'
            Write-Host ' 3 - Search for a computer '
            Write-Host ' 4 - Search for an Organisational Unit (OU)'
            Write-Host ' 5 - Create a new user'
            Write-Host ' 6 - Set a users OU'
            Write-Host ' 7 - Set a computers OU'
            Write-Host ' 8 - Set a users Password'
            Write-Host ' 9 - Exit'
            Write-Host ' '
            Write-Host ' '
            Start-Menu
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'Password sucessfully changed for user'$user -ForegroundColor Green
                      Write-Host ' '
                    }
        }
}

###############
# Exit Script #
###############
Function Exit-Script {
Param (

)
Begin {
}
Process {
        Try {
            exit
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'Password sucessfully changed for user'$user -ForegroundColor Green
                      Write-Host ' '
                    }
        }
}

###################
# Pause for input #
###################
Function Pause-ForInput {
Param (

)
Begin {
}
Process {
        Try {
            Write-Host -NoNewLine 'Press any key to continue...';
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'Password sucessfully changed for user'$user -ForegroundColor Green
                      Write-Host ' '
                    }
        }
}

Function pause ($message)
{
    # Check if running Powershell ISE
    if ($psISE)
    {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("$message")
    }
    else
    {
        Write-Host "$message" -ForegroundColor Yellow
        $x = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#Script Execution goes here

#NewUser
#RandomDefaultPassword
#SetUserOU
#searchou
#searchcomputer
#searchuser
#SetUserPW


Start-Script
            
## TO DO
##
## > Fix pause for user input
## > Amend each function ending and pausing for input

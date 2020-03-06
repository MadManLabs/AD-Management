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
$script:password = $null
$script:SecurePassword = $null
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

function Test-Password {
Param ()
Begin {
    Write-Host "Script starting"
    }
Process {
    Try {
        ###########
        #Variables#
        ###########

       $script:SecurePassword
       $script:password
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

#########################
# RandomDefaultPassword #
#########################
Function RandomDefaultPassword {
Param ()
Begin {
}
Process {
        Try {
            $rand = Get-Random -Maximum 999
            $script:password = 'Welcome=' + $rand
            $script:SecurePassword = $script:password | ConvertTo-SecureString -AsPlainText -Force 
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'Random Password is:' $script:password
                      Write-Host ' '
                      Pause-ForInput
                      Start-Options
                    }
        }
}

########################
# RandomSecurePassword #
########################
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
            $script:password = 'Welcome=' + $rand
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host 'Random Complex Password is:' $script:password
                      Write-Host ' '
                      Pause-ForInput
                      Start-Options
                    }
        }
}

##################################################
#                                           Users#
##################################################

##############
# SearchUser #
##############
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
                      Pause-ForInput
                      Start-Options
                    }
        }
}

###########
# NewUser #
###########
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
        $suser = $surname+$givenname.substring(0,1)+'100'
        #Defines the logon in UPN format with the FQDN appended to the end
        $upn = $suser + '@' + $domain.ToLower()
        #Defines the logon pre-pended by the domain as per user logon
        $logon = $domshort + '\' + $suser.ToLower()
        #Sets a default password, this could be made user definable if desired rather than a hard coded password.
        #$rand = Get-Random -Maximum 9999 -Minimum 1000
        #$plainpassword = 'Welcome=' + $rand   
        #$script:securepassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force 
        #What OU would the user created in
        $oupath = Read-Host 'What OU is the user to be created in? Format: OU=X,OU=Y,OU=Z,DC=ABC,DC=DEF'
        #$ou = 'OU=Users,OU=Accounts,OU=CPT'
        #$oupath = $ou + ',' + $dn
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
        Write-Host 'SAM Name:                  '-Foregroundcolor Yellow -nonewline; Write-Host $suser -ForegroundColor Green
        Write-Host 'Password:                  ' -Foregroundcolor Yellow -nonewline; Write-Host $script:Password -ForegroundColor Green
        #Write-Host 'The user must change their password on logon!' -ForegroundColor Magenta
        #Write-Host ''
        #Write-Host 'Logon:              ' -Foregroundcolor Yellow -nonewline; Write-Host $logon -ForegroundColor Green
        #Write-Host ''
        #Write-Host 'Organizational Unit:       ' -ForegroundColor Yellow -NoNewline; Write-Host $oupath -ForegroundColor Green
        #Write-Host ''
     
        New-ADUser -GivenName $givenname -Surname $surname -Name $fullname -DisplayName $displayname -SamAccountName $suser -UserPrincipalName $upn -ChangePasswordAtLogon:$true -AccountPassword $script:SecurePassword -Enabled:$true -Path $oupath
        #Write-Host ''
        $udn = Get-ADUser -Filter 'SamAccountName -eq $suser' | select -ExpandProperty DistinguishedName
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
      Pause-ForInput
     Start-Options
    }
  }
}

##############
# RemoveUser #
##############
function RemoveUser {
Param ()
Begin {
    Write-Host "Removing a user..."
    }
Process {
    Try {
        ###########
        #Variables#
        ###########
        Write-Host ' Not implemented yet'
        $suser = Read-Host 'What is the username of the user you want to remove?'

        Remove-ADUser -Identity $suser -Confirm:$false
        }
        Catch {
      Write-Host -BackgroundColor Red "Error: $($_.Exception)"
      Break
    }
  }
  End {
    If ($?) {
      Write-Host 'User Removed Successfully.'
      Write-Host ' '
      Pause-ForInput
     Start-Options
    }
  }
}

#############
# SetUserOU #
#############
Function SetUserOU {
Param ()
Begin {
}
Process {
        Try {
            ###########
            #Variables#
            ###########
            $suser = Read-Host 'Enter the users logonname in SAM Account Format'
            $udn = Get-ADUser -Filter 'SamAccountName -eq $suser' | select -ExpandProperty DistinguishedName
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
                      Pause-ForInput
                      Start-Options
                    }
        }
}

##################
# AddUserToGroup #
##################
Function AddUserToGroup {
Param ()
Begin {
}
Process {
        Try {
            ###########
            #Variables#
            ###########
            $suser = Read-Host 'Enter the users logonname in SAM Account Format'
            $secgroup = Read-Host 'Enter the Security Group to add the user to'

            Add-ADGroupMember -Identity $secgroup -Members $suser
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host $suser 'added to' $secgroup 'successfully'
                      Write-Host ' '
                      Pause-ForInput
                      Start-Options
                    }
        }
}

#######################
# RemoveUserFromGroup #
#######################
Function RemoveUserFromGroup {
Param ()
Begin {
}
Process {
        Try {
            ###########
            #Variables#
            ###########
            $suser = Read-Host 'Enter the users logon name in SAM Account Format'
            $secgroup = Read-Host 'Enter the Security Group to remove the user from'

            Remove-ADGroupMember -Identity $secgroup -Members $suser -Confirm:$false
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host $suser 'removed from' $secgroup 'successfully'
                      Write-Host ' '
                      Pause-ForInput
                      Start-Options
                    }
        }
}

##############
# EnableUser #
##############
Function EnableUser {
Param ()
Begin {
}
Process {
        Try {
            ###########
            #Variables#
            ###########
            $suser = Read-Host 'Enter the users logon name in SAM Account Format'
            
            Set-ADUser -Identity $suser -Enabled:$true
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host $suser 'enabled successfully'
                      Write-Host ' '
                      Pause-ForInput
                      Start-Options
                    }
        }
}

###############
# DisableUser #
###############
Function DisableUser {
Param ()
Begin {
}
Process {
        Try {
            ###########
            #Variables#
            ###########
            $suser = Read-Host 'Enter the users logon name in SAM Account Format'
            
            Set-ADUser -Identity $suser -Enabled:$false
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            Break
            }
        }
        End {
            If ($?) {
                      Write-Host $suser 'disabled successfully'
                      Write-Host ' '
                      Pause-ForInput
                      Start-Options
                    }
        }
}

#############
# SetUserPW #
#############
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
            $udn = Get-ADUser -Filter 'SamAccountName -eq $suser' | select -ExpandProperty DistinguishedName
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
                      Pause-ForInput
                      Start-Options
                    }
        }
}

##################################################
#                                       Computers#
##################################################

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
                      Pause-ForInput
                      Start-Options
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
            $udn = Get-ADUser -Filter 'SamAccountName -eq $suser' | select -ExpandProperty DistinguishedName
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
                      Pause-ForInput
                      Start-Options
                    }
        }
}

##################################################
#                                          Groups#
##################################################



##################################################
#                                          Script#
##################################################

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
                2 { SearchOU }
                3 { CreateOU }
                4 { RemoveOU }
                5 { SearchUser }
                6 { NewUser }
                7 { RemoveUser }
                8 { SetUserOU }
                9 { AddUserToGroup }
                10 { RemoveUserFromGroup }
                11 { EnableUser }
                12 { DisableUser }
                13 { ResetUserPW }
                14 { SearchComputer }
                15 { SetComputerOU }
                16 { EnableComputer }
                17 { DisableComputer }
                18 { SearchSecGroup }
                19 { NewSecGroup }
                20 { RemoveSecGroup }
                21 { AddUserToSecGroup }
                22 { RemoveUserFromSecGroup }
                23 { ListUsersInSecGroup }
                24 { Exit }
                25 { test-password }
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
            Write-Host '  Misc '
            Write-Host ' ======'
            Write-Host '  0 - Generate a random Default Password '
            Write-Host '  1 - Generate a random Secure Password '
            Write-Host ' '
            Write-Host '  Organisational Units (OU)'
            Write-Host ' ==========================='
            Write-Host ' '
            Write-Host '  2 - Search OU'
            Write-Host '  3 - Create OU'
            Write-Host '  4 - Remove OU'
            Write-Host ' '
            Write-Host '  Users'
            Write-Host ' ======='
            Write-Host '  5 - Search for a User'
            Write-Host '  6 - Add a User'
            Write-Host '  7 - Remove a User'
            Write-Host '  8 - Set User OU'
            Write-Host '  9 - Add User to group'
            Write-Host ' 10 - Remove User from group'
            Write-Host ' 11 - Enable User'
            Write-Host ' 12 - Disable User'
            Write-Host ' 13 - Reset User password'
            Write-Host ' '
            Write-Host '  Computers'
            Write-Host ' ==========='
            Write-Host ' 14 - Search for a Computer '
            Write-Host ' 15 - Set Computer OU'
            Write-Host ' 16 - Enable Computer'
            Write-Host ' 17 - Disable Computer'
            Write-Host ' '
            Write-Host '  Groups'
            Write-Host ' ========'
            Write-Host ' 18 - Search Security Groups'
            Write-Host ' 19 - Create a Security Group'
            Write-Host ' 20 - Remove a Security Group'
            Write-Host ' 21 - Add User to a Security Group '
            Write-Host ' 22 - Remove User from a Security Group '
            Write-Host ' 23 - List Users in a Security Group '
            Write-Host ' '
            Write-Host ' 24 - Exit Script'
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
            [String]$pauseforinput = $(Write-Host 'Press '-NoNewLine; Write-Host '[ENTER]' -ForegroundColor Yellow -NoNewline; Write-Host ' to continue...'; Read-Host)
            }
            Catch {
            Write-Host -BackgroundColor Red "Error: $($_.Exception)"
            }
        }
        End {
            If ($?) {
                      Write-Host 'Password sucessfully changed for user'$user -ForegroundColor Green
                      Write-Host ' '
                    }
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
## > Re-Order functions for ease of reading
## > Add functions for Remove User
## > Add functions for Set user Group
## > Add functions for Remove from user group
## > Add functions for Enable Accountr
## > Add functions for Disable Account
## > Add functions for Lock Workstation?
## > Add functions for search groups
## > Add functions for Create Group
## > Add functions for Remove Group
## > Add functions for Add members to group
## > Add functions for Remove members from group

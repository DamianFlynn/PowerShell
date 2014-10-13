workflow New-ADDelegatedOfficeOU {
    param (
        [string] $Site = "WAL",
		[string] $BaseOUPath = "ou=!Offices,dc=corpnet,dc=liox,dc=org",
		[string] $DelegationGroupOUPath = "ou=Administration,ou=Delegations,dc=corpnet,dc=liox,dc=org"
    )



	#region Load PowerShell Modules

	
	#endregion
	
	#region OU Supporting Functions
	#Establish the Delegation Group if necessary
	function New-ADDelegationGroup {
			Param (
			[string] $Site,
			[string] $DelegationGroupOUPath
		)
		
		begin {
			import-module activedirectory
		}

		process {
			# Try to create the Delegation Group, this may fail if the group already exists
            Try {
			    $delegationGroup = New-ADGroup -Name ("!CORP delegation IT " + $Site + " OU Admin")   -SamAccountName ("!CORP delegation IT " + $Site + " OU Admin") -GroupCategory Security -GroupScope Universal -DisplayName ("!CORP delegation IT " + $Site + " OU Administration") -Path $DelegationGroupOUPath -Description "Delegation access for IT to Manage the $SITE site OU in AD" -Passthru
            }

			# If the creation failed, check the error to see if the message was that the group already exists, and if so get the groups details
            Catch {
                if ($_.Exception.Message -like "The specified group already exists") {
                    $delegationGroup = Get-ADGroup -identity ("!CORP delegation IT " + $Site + " OU Admin")
                }
            }

			#Add-ADGroupMember -Identity $delegationGroup -Members ("!$Site IT (Standard)")
			$DelegatedAccount = $DelegationGroup.SAMAccountName

			return $DelegationGroup.SAMAccountName
		}
	}

	#Establish the OU if necessary
	function New-ADOU {
		param (
			[string] $Path
		)

		begin {
			import-module activedirectory
		}

		process {
			$OUBranch = $Path -split ","
			[array]::reverse($OUBranch)
			$LDAPPath = ""

			# Traverse each branch of the OU in sequence
			foreach ($pathNode in $OUBranch)
			{
				
				# Check to see if the current branch is an Organisational Unit
				if($pathNode -like "ou=*")
				{
                    $objectinfo = $pathNode.Length
                    $thisName =$pathNode -replace 'ou=',''
                    try {
						New-ADOrganizationalUnit -Name $thisName -path $LDAPPath
					}

					catch {
						if ($_.Exception.Message -like "An attempt was made to add an object to the directory with a name that is already in use") {
							write-Verbose "Not Creating OU, already exists: "  $pathNode "," $LDAPPath
						}
					}
				}

				if ($LDAPPath -eq "") { 
					$LDAPPath = $pathNode 
				} else {
					$LDAPPath = $pathNode + "," + $LDAPPath
				}
			}
		}
	}

	#endregion

	#region AD Delegation Function

	# Get-ADObjectAcl -Name "ou=Employees,ou=Users,ou=MAD,ou=Office,dc=diginerve,dc=net" | ? {Inherited -eq $false} | ? {$_.NTAccount -like "DIGINERVE\*"} | select InheritedObjectType, ObjectType, ActiveDirectghts, InheritanceType | fl
	function Get-ADObjectAcl {
	<#
	.DESCRIPTION
	Gets the ACLs from an LDAP Object
	.EXAMPLE
	Import-Module ActiveDirectory
	Get-ADObjectAcl -Name "ou=Mobile,ou=Computers,ou=Test2,ou=!Offices,dc=corpnet,dc=liox,dc=org"
	.EXAMPLE
	Get-ADObjectAcl -Name "ou=Mobile,ou=Computers,ou=Test2,ou=!Offices,dc=corpnet,dc=liox,dc=org"  | ? {$_.IsInherited -eq $false} | ? {$_.NTAccount -like "CORPNET\*"}
	#>
		[CmdletBinding()]
		param(
			[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)]
			[ValidateNotNullOrEmpty()]
			[System.String]
			$Name
		)

		process {
			$ADObject = [ADSI]"LDAP://$Name"
			$aclObject = $ADObject.psbase.ObjectSecurity

			$aclList = $aclObject.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])
         
			foreach($acl in $aclList)
			{
				$objSID = New-Object System.Security.Principal.SecurityIdentifier($acl.IdentityReference)
            
				$info = @{
					'ActiveDirectoryRights' = $acl.ActiveDirectoryRights;
					'InheritanceType' = $acl.InheritanceType;
					'ObjectType' = $acl.ObjectType;
					'InheritedObjectType' = $acl.InheritedObjectType;
					'ObjectFlags' = $acl.ObjectFlags;
					'AccessControlType' = $acl.AccessControlType;
					'IdentityReference' = $acl.IdentityReference;
					'NTAccount' = $objSID.Translate( [System.Security.Principal.NTAccount] );
					'IsInherited' = $acl.IsInherited;
					'InheritanceFlags' = $acl.InheritanceFlags;
					'PropagationFlags' = $acl.PropagationFlags;
				}
            
				$obj = New-Object -TypeName PSObject -Property $info
				$obj.PSObject.typenames.insert(0,'DigiNerve.AD.LDAPAcls')
				Write-Output $obj
			}
		}
	}

	#Function to Add new Delegation Permission to an OU

    function New-ADDelegationAccessRule {
        param (
            [string] $LDAPPath,
            [string] $Identity,
            [string] $ActiveDirectoryRights,
            [string] $AccessControlType = "Allow",
            [GUID]   $ObjectType,
            [string] $InheritanceType,
            [GUID]   $InheritedObjectType
        )

        Process
        {
            
            #region sidevaluation

            #$Identity = "NT AUTHORITY\NETWORK SERVICE"
            
            #$Identity = "Damian Flynn"
            #if ($Identity -like '*\*' -and $Identity -notlike 'BUILTIN*' -and $Identity -notlike 'NT AUTHORITY*') {
            #    Write-Host $Identity
            #    $SamAccountName = $Identity.Split('\')[1]
            #} else {
            #    $SamAccountName = $Identity
            #}
            #Write-Host $SamAccountName


            #$ADObject = Get-ADObject -Filter ('SamAccountName -eq "{0}"' -f $SamAccountName)
            #Write-Host $ADObject

            #endregion

            $ADObject = Get-ADGroup $Identity
            $ADObjectSID = new-object System.Security.Principal.SecurityIdentifier $ADObject.SID
                
            $ADObject = [ADSI]("LDAP://" + $LDAPPath)

            $ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $ADObjectSID, $ActiveDirectoryRights,$AccessControlType,$ObjectType,$InheritanceType,$InheritedObjectType
            $ADObject.ObjectSecurity.AddAccessRule($ace)
            $ADObject.CommitChanges()

        }
    }

	#endregion

	#region Computer Object Delegations

    function New-ADDelegationComputerObjectsWriteSPN {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            $guidWriteSPN            = New-Object Guid f3a64788-5306-11d1-a9c5-0000f80367c1
            $guidComputerObject      = new-object Guid bf967a86-0de6-11d0-a285-00aa003049e2

	        # ObjectType            : f3a64788-5306-11d1-a9c5-0000f80367c1
            # InheritanceType       : Descendents
            # InheritedObjectType   : bf967a86-0de6-11d0-a285-00aa003049e2
            # ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
            # ActiveDirectoryRights : WriteProperty
    
            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidWriteSPN -InheritanceType "Descendents" -InheritedObjectType $guidComputerObject
        }

    }
    
    function New-ADDelegationComputerObjectsCreateDelete {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs

            $guidNull                = new-object Guid 00000000-0000-0000-0000-000000000000
            $guidComputerObject      = new-object Guid bf967a86-0de6-11d0-a285-00aa003049e2 

            # Delegation for Create and Delete Child Computer Objects
            # ACL = Allow: This Object and all Decendant objects - Create Computer Object, Delete Computer Object

            # ObjectType            : bf967a86-0de6-11d0-a285-00aa003049e2
            # InheritanceType       : All
            # InheritedObjectType   : 00000000-0000-0000-0000-000000000000
            # ActiveDirectoryRights : CreateChild, DeleteChild

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "CreateChild, DeleteChild" -ObjectType $guidComputerObject -InheritanceType "Descendents" -InheritedObjectType $guidNull            
        }

    } 
 
    function New-ADDelegationComputerObjectsFullControl {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs

            $guidNull                = new-object Guid 00000000-0000-0000-0000-000000000000
            $guidComputerObject      = new-object Guid bf967a86-0de6-11d0-a285-00aa003049e2 


            # Delegation for Full Control Child Computer Objects
            # ACL = Allow: Decendant Computer objects - Full Control

			# ObjectType            : 00000000-0000-0000-0000-000000000000
            # InheritanceType       : Descendents
            # InheritedObjectType   : bf967a86-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : GenericAll
            
            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "GenericAll" -ObjectType $guidNull -InheritanceType "Descendents" -InheritedObjectType $guidComputerObject
        }

    } 
 
	#endregion
	
	#region Computer Object Proxy Delegation

	function New-ADDelegationComputerObjectsManagement {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        { 
            New-ADDelegationComputerObjectsCreateDelete -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
            New-ADDelegationComputerObjectsFullControl -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
        }
    }

	#endregion

	#region Group Object Delegations

    function New-ADDelegationGroupObjectsMembership {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs

            $guidGroupObject          = new-object Guid BF967A9C-0DE6-11D0-A285-00AA003049E2
            $guidGroupMembers         = new-object Guid bf9679c0-0de6-11d0-a285-00aa003049e2

            # Delegation for Full Control Child Computer Objects
            # ACL = Allow: Decendant Group objects - Read Membership, Write Membership

            # ObjectType            : bf9679c0-0de6-11d0-a285-00aa003049e2
            # InheritanceType       : Descendents
            # InheritedObjectType   : bf967a9c-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : ReadProperty, WriteProperty

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidGroupMembers -InheritanceType "Descendents" -InheritedObjectType $guidGroupObject
        }

    } 

    function New-ADDelegationGroupObjectsManager {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs

            $guidGroupObject          = new-object Guid BF967A9C-0DE6-11D0-A285-00AA003049E2
            $guidGroupManagers        = new-object Guid 0296c120-40da-11d1-a9c0-0000f80367c1

            # Delegation for Full Control Child Computer Objects
            # ACL = Allow: Decendant Group objects - Read Membership, Write Membership

            # InheritedObjectType   : bf967a9c-0de6-11d0-a285-00aa003049e2
            # ObjectType            : 0296c120-40da-11d1-a9c0-0000f80367c1
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents


            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidGroupManagers -InheritanceType "Descendents" -InheritedObjectType $guidGroupObject
        }

    } 

    function New-ADDelegationGroupObjectsCreateDelete {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs

            $guidNull                = new-object Guid 00000000-0000-0000-0000-000000000000
            $guidGroupObject         = new-object Guid bf967a9c-0de6-11d0-a285-00aa003049e2

            # Delegation for Create and Delete Child Group Objects
            # ACL = Allow: This Object and all Decendant objects - Create Group Object, Delete Group Object
            # ObjectType            : bf967a86-0de6-11d0-a285-00aa003049e2
            # InheritanceType       : All
            # InheritedObjectType   : 00000000-0000-0000-0000-000000000000
            # ActiveDirectoryRights : CreateChild, DeleteChild

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "CreateChild, DeleteChild" -ObjectType $guidGroupObject -InheritanceType "Descendents" -InheritedObjectType $guidNull            
        }

    } 
 
    function New-ADDelegationGroupObjectsFullControl {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs

            $guidNull                = new-object Guid 00000000-0000-0000-0000-000000000000
            $guidGroupObject         = new-object Guid bf967a9c-0de6-11d0-a285-00aa003049e2


            # Delegation for Full Control Child Computer Objects
            # ACL = Allow: Decendant Group objects - Full Control

            # ObjectType            : 00000000-0000-0000-0000-000000000000
            # InheritanceType       : Descendents
            # InheritedObjectType   : bf967a86-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : GenericAll
            # 


            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "GenericAll" -ObjectType $guidNull -InheritanceType "Descendents" -InheritedObjectType $guidGroupObject
        }

    } 
 
	#endregion

	#region Group Object Proxy Delegations

    function New-ADDelegationGroupObjectsManagement {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        { 
            New-ADDelegationGroupObjectsCreateDelete -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
            New-ADDelegationGroupObjectsFullControl -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
        }
    }
 
	#endregion

	#region User Object Delegations

	## AD Attributes ###########::# PowerShell Function ########## 
	#							
	# userPrincipalName
	# userAccountControl
	# title
	# telephoneNumber
	# streetAddress
	# st
	# sn
	# postalCode
	# mobile
	# manager
	# mail
	# l
	# givenName
	# facsimileTelephoneNumber
	# extensionAttribute1
	# extensionAttribute2
	# extensionAttribute4
	# extensionAttribute14
	# displayName
	# description				:: Read/write Department
	# company
	# co
	# cn
	# c 
	#							:: Read/write Web Page Address
	#							:: Read/write thumbnailPhoto
	#							:: Read/write thumbnailLogo
	#							:: Read/write secretary
	#							:: Read/write roomNumber
	#							:: Read/write profilePath
	#							:: Read/write photo
	#							:: Read/write Notes
	#							:: Read/write Mobile Number
	#							:: Read/write Mobile Number (Others)
	#							:: Read/write lockoutTime
	#							:: Read/write jpegPhoto
	#							:: Read/write Home Phone
	#							:: Read/write Home Phone Number (Others)
	#							:: Read/write Home Folder
	#							:: Read/write Home Address
	#							:: Read/write Fax Number (Others)
	#							:: Read/write Fax Number
	#							:: Read/write Comment
	#							:: Read/write Assistant
	#							:: Read/write web information
	#							:: Reset password
	#							:: Change password


    function New-ADDelegationUserObjectsPhoto {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			## Read/write photo
			$guidUserObject = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserPhoto  = new-object Guid 9c979768-ba1a-4c08-9632-c6a5c1ed649a

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : 9c979768-ba1a-4c08-9632-c6a5c1ed649a
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents


            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserPhoto -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

    function New-ADDelegationUserObjectsThumbnailLogo {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write User thumbnailLogo
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserthumbnailLogo = new-object Guid bf9679a9-0de6-11d0-a285-00aa003049e2

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : bf9679a9-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserthumbnailLogo -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	function New-ADDelegationUserObjectsThumbnailPhoto {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write thumbnailPhoto
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserthumbnailPhoto = new-object Guid 8d3bca50-1d7e-11d0-a081-00aa006c33ed

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : 8d3bca50-1d7e-11d0-a081-00aa006c33ed
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserthumbnailPhoto -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	function New-ADDelegationUserObjectsJPEGPhoto {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write jpegPhoto
			$guidUserObject = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserJPEGPhoto = new-object Guid bac80572-09c4-4fa9-9ae6-7628d7adbe0e

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : bac80572-09c4-4fa9-9ae6-7628d7adbe0e
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserJPEGPhoto -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

    function New-ADDelegationUserObjectsHomePhone {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write Home Phone
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserHomePhone = new-object Guid f0f8ffa1-1191-11d0-a060-00aa006c33ed

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : f0f8ffa1-1191-11d0-a060-00aa006c33ed
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserHomePhone -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

    function New-ADDelegationUserObjectsHomePhoneOther {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write Home Phone (Other)
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserHomePhoneOther = new-object Guid f0f8ffa2-1191-11d0-a060-00aa006c33ed

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : f0f8ffa2-1191-11d0-a060-00aa006c33ed
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserHomePhoneOther -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

    function New-ADDelegationUserObjectsMobileNumber {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write Mobile Number
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserMobileNumber = new-object Guid f0f8ffa3-1191-11d0-a060-00aa006c33ed

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : f0f8ffa3-1191-11d0-a060-00aa006c33ed
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserMobileNumber -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	function New-ADDelegationUserObjectsMobileNumberOther {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write User Mobile Other
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserMobileNumberOther = new-object Guid 0296c11e-40da-11d1-a9c0-0000f80367c1

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : 0296c11e-40da-11d1-a9c0-0000f80367c1
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserMobileNumberOther -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 
	
	function New-ADDelegationUserObjectsFaxNumber {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write Fax Number
			$guidUserObject = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserFaxNumber = new-object Guid bf967974-0de6-11d0-a285-00aa003049e2

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : bf967974-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserFaxNumber -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 
	
    function New-ADDelegationUserObjectsFaxNumberOther {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write Fax Number (Others)
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserFaxNumberOther = new-object Guid 0296c11d-40da-11d1-a9c0-0000f80367c1

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : 0296c11d-40da-11d1-a9c0-0000f80367c1
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserFaxNumberOther -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	function New-ADDelegationUserObjectsJobTitle {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write User Assistant
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserTitle   = new-object Guid bf967a55-0de6-11d0-a285-00aa003049e2
											   
            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : bf967a55-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserTitle -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	function New-ADDelegationUserObjectsDescription {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write User Assistant
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserDescription   = new-object Guid bf967950-0de6-11d0-a285-00aa003049e2

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : bf967950-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserDescription -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	function New-ADDelegationUserObjectsComment {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			## Read/write Comment
			$guidUserObject = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserComment = new-object Guid bf967a6a-0de6-11d0-a285-00aa003049e2

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : bf967a6a-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserComment -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	function New-ADDelegationUserObjectsNotes {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write Comments
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserNotes     = new-object Guid bf96793e-0de6-11d0-a285-00aa003049e2

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : bf96793e-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserNotes -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 
  
    function New-ADDelegationUserObjectsHomeAddress {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write Home Address
			$guidUserObject = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserHomeAddress = new-object Guid 16775781-47f3-11d1-a9c3-0000f80367c1

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : 16775781-47f3-11d1-a9c3-0000f80367c1
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserHomeAddress -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

    function New-ADDelegationUserObjectsRoomNumber {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write roomNumber
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserRoomNumber = new-object Guid 81d7f8c2-e327-4a0d-91c6-b42d4009115f

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : 81d7f8c2-e327-4a0d-91c6-b42d4009115f
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserRoomNumber -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	function New-ADDelegationUserObjectsCompany {
		param (
	        [string] $LDAPPath,
			[string] $DelegatedAccount
		)

		process
		{
			# AD GUID Object IDs
			#Read/write User Assistant
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserCompany   = new-object Guid f0f8ff88-1191-11d0-a060-00aa006c33ed
	
		    # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
	        # ObjectType            : f0f8ff88-1191-11d0-a060-00aa006c33ed
			# ActiveDirectoryRights : ReadProperty, WriteProperty
			# InheritanceType       : Descendents

			New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserCompany -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
		}

    } 

    function New-ADDelegationUserObjectsDepartment {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write department
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserDepartment = new-object Guid bf96794f-0de6-11d0-a285-00aa003049e2

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : bf96794f-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserDepartment -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 
    
    function New-ADDelegationUserObjectsWebInformation {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write web information
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserWebInformation = new-object Guid e45795b3-9455-11d1-aebd-0000f80367c1

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : e45795b3-9455-11d1-aebd-0000f80367c1
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserWebInformation -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

    function New-ADDelegationUserObjectsWebPageAddress {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write Web Page Address
			$guidUserObject = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserWWWPage = new-object Guid bf967a7a-0de6-11d0-a285-00aa003049e2

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : bf967a7a-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserWWWPage -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	function New-ADDelegationUserObjectsManager {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write User Assistant
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserManager   = new-object Guid bf9679b5-0de6-11d0-a285-00aa003049e2

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : bf9679b5-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserManager -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	function New-ADDelegationUserObjectsUserAssistant {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write User Assistant
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserAssistant = new-object Guid 0296c11c-40da-11d1-a9c0-0000f80367c1

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : 0296c11c-40da-11d1-a9c0-0000f80367c1
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserAssistant -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	function New-ADDelegationUserObjectsSecretary {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write secretary
			$guidUserObject = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserSecretary = new-object Guid 01072d9a-98ad-4a53-9744-e83e287278fb

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : 01072d9a-98ad-4a53-9744-e83e287278fb
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserSecretary -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

    function New-ADDelegationUserObjectsHomeFolder {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write Home Folder
			$guidUserObject = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserHomeDirectory = new-object Guid bf967985-0de6-11d0-a285-00aa003049e2

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : bf967985-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserHomeDirectory -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

    function New-ADDelegationUserObjectsProfilePath {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write Profile Path
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserProfilePath = new-object Guid bf967a05-0de6-11d0-a285-00aa003049e2

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : bf967a05-0de6-11d0-a285-00aa003049e2
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserProfilePath -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	function New-ADDelegationUserObjectsGroupMembership {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write Profile Path
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserGroupMembership = new-object Guid bc0ac240-79a9-11d0-9020-00c04fc2d4cf

			# InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
			# ObjectType            : bc0ac240-79a9-11d0-9020-00c04fc2d4cf
			# ActiveDirectoryRights : ReadProperty, WriteProperty
			# InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserGroupMembership -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

    function New-ADDelegationUserObjectsLockoutTime {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write lockoutTime
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserLockoutTime = new-object Guid 28630ebf-41d5-11d1-a9c1-0000f80367c1

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : 28630ebf-41d5-11d1-a9c1-0000f80367c1
            # ActiveDirectoryRights : ReadProperty, WriteProperty
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ReadProperty, WriteProperty" -ObjectType $guidUserLockoutTime -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	function New-ADDelegationUserObjectsResetPassword {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/write Reset Password
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserResetPassword = new-object Guid 00299570-246d-11d0-a768-00aa006e0529
			
            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : 00299570-246d-11d0-a768-00aa006e0529
            # ActiveDirectoryRights : ExtendedRight
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ExtendedRight" -ObjectType $guidUserResetPassword -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

    function New-ADDelegationUserObjectsChangePassword {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs
			#Read/Write Change Password
			$guidUserObject    = new-object Guid bf967aba-0de6-11d0-a285-00aa003049e2
			$guidUserChangePassword = new-object Guid ab721a53-1e2f-11d0-9819-00aa0040529b

            # InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
            # ObjectType            : ab721a53-1e2f-11d0-9819-00aa0040529b
            # ActiveDirectoryRights : ExtendedRight
            # InheritanceType       : Descendents

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "ExtendedRight" -ObjectType $guidUserChangePassword -InheritanceType "Descendents" -InheritedObjectType $guidUserObject
        }

    } 

	#endregion

	#region User Object Proxy Delegations

	function New-ADDelegationUserObjectsPasswordandLockout {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        { 
			New-ADDelegationUserObjectsLockoutTime -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsResetPassword -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsChangePassword -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
        }
    }
 
    function New-ADDelegationUserObjectsAttributeGroup1 {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        { 
            New-ADDelegationUserObjectsPhoto -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
            New-ADDelegationUserObjectsThumbnailLogo -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsThumbnailPhoto -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsJPEGPhoto -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsHomePhone -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsMobileNumber -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsMobileNumberOther -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsComment -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsNotes -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsHomeAddress -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsRoomNumber -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsDepartment -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsWebInformation -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsWebPageAddress -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsUserAssistant -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsSecretary -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsHomeFolder -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsProfilePath -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
        }
    }
 
	function New-ADDelegationUserObjectsAttributeGroup2 {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

    
		process
        { 
		    New-ADDelegationUserObjectsManager -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
            New-ADDelegationUserObjectsCompany -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsJobTitle -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsDescription -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsDepartment -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsComment -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
			New-ADDelegationUserObjectsNotes -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
        }
	}

	#endregion

	#region Contact Object Delegations

    function New-ADDelegationContactObjectsCreateDelete {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs

            $guidNull                = new-object Guid 00000000-0000-0000-0000-000000000000
            $guidContactObject      = new-object Guid 5cb41ed0-0e4c-11d0-a286-00aa003049e2

            # Delegation for Create and Delete Child Computer Objects
            # ACL = Allow: This Object and all Decendant objects - Create Computer Object, Delete Computer Object

            # ObjectType            : 5cb41ed0-0e4c-11d0-a286-00aa003049e2
            # InheritanceType       : All
            # InheritedObjectType   : 00000000-0000-0000-0000-000000000000
            # ActiveDirectoryRights : CreateChild, DeleteChild

            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "CreateChild, DeleteChild" -ObjectType $guidContactObject -InheritanceType "Descendents" -InheritedObjectType $guidNull            
        }
    } 
 
    function New-ADDelegationContactObjectsFullControl {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        {
            # AD GUID Object IDs

            $guidNull                = new-object Guid 00000000-0000-0000-0000-000000000000
            $guidContactObject      = new-object Guid 5cb41ed0-0e4c-11d0-a286-00aa003049e2


            # Delegation for Full Control Child Computer Objects
            # ACL = Allow: Decendant Computer objects - Full Control

			# ObjectType            : 00000000-0000-0000-0000-000000000000
            # InheritanceType       : Descendents
            # InheritedObjectType   : 5cb41ed0-0e4c-11d0-a286-00aa003049e2
            # ActiveDirectoryRights : GenericAll
            
            New-ADDelegationAccessRule -LDAPPath $LDAPPath -Identity $DelegatedAccount -ActiveDirectoryRights "GenericAll" -ObjectType $guidNull -InheritanceType "Descendents" -InheritedObjectType $guidContactObject
        }

    } 
 
	#endregion
	
	#region Contact Object Proxy Delegation

	function New-ADDelegationContactObjectsManagement {
        param (
            [string] $LDAPPath,
            [string] $DelegatedAccount
        )

        process
        { 
            New-ADDelegationContactObjectsCreateDelete -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
            New-ADDelegationContactObjectsFullControl -LDAPPath $LDAPPath -DelegatedAccount $DelegatedAccount
        }
    }

	#endregion
		
	#region Define the OU Structure and Delegations

	
	$HelpdeskTeam = "Helpdesk"
	$OfficeITTeam = New-ADDelegationGroup -Site $Site -DelegationGroupOUPath $DelegationGroupOUPath
    
	# OU Structure                  | Site IT Delegation                                    | Helpdesk Delegation
	#
	# OU = Site					
	#	OU = Computers
	#		OU = Disabled			| Computer Objects: Create, Delete, Full Control		| Computer Objects: Create, Delete, Full Control
	#		OU = Mobile				| Computer Objects: Create, Delete, Full Control		| Computer Objects: Create, Delete, Full Control
	#		OU = Workstations		| Computer Objects: Create, Delete, Full Control		| Computer Objects: Create, Delete, Full Control
	#		OU = Servers			| Computer Objects: Create, Delete, Full Control		| Computer Objects: Create, Delete, Full Control
	#	OU = Groups
	#		OU = Local				| Group Objects: Create, Delete, Full Control			|
	#		OU = Standard			| Group Objects: Manage Membership, Assign Manager		|
	#	OU = Users
	#		OU = Disabled			| No Permissions										| User Objects: Delete 
	#		OU = Contacts			| Contact Objects: Create, Delete, Full Control			|
	#		OU = Employees			| User Objects: Management of [*Attributes Group 1]		|
	#		OU = Services			| User Objects: Management of [*Attributes Group 1]		|
	#		OU = Mailboxes			| User Objects: Management of [*Attributes Group 2]		|
	#
	#
	# Attributes Group 1
	# User Objects: Photo, ThumbnailLogo, ThumbnailPhoto, JPEGPhoto, HomePhone, MobileNumber, MobileNumberOther, Comments, Notes, HomeAddress, RoomNumber, Department, 
	#               WebInformation, WebPageAddress, UserAssistant, Secretary, HomeFolder, ProfilePath, LockoutTime, ResetPassword, ChangePassword
	#
	# Attributes Group 2
	# User Objects: Manager, Company, JobTitle, Decription, Department, Comments, Notes



    $ConfigurationData = @{
        AllNodes = @(
            #Computer OU
            @{OUName = 'ou=Disabled,ou=Computers';     Roles=@( @{Group=$OfficeITTeam;	Permission=@('ComputersCreateDelete','ComputersFullControl')}
                                                                @{Group=$HelpdeskTeam;	Permission=@('ComputersCreateDelete','ComputersFullControl')} )},
            @{OUName = 'ou=Servers,ou=Computers';      Roles=@( @{Group=$OfficeITTeam;	Permission=@('ComputersCreateDelete','ComputersFullControl')}
                                                                @{Group=$HelpdeskTeam;	Permission=@('ComputersCreateDelete','ComputersFullControl')} )},
            @{OUName = 'ou=Workstations,ou=Computers'; Roles=@( @{Group=$OfficeITTeam;	Permission=@('ComputersCreateDelete','ComputersFullControl')}
                                                                @{Group=$HelpdeskTeam;	Permission=@('ComputersCreateDelete','ComputersFullControl')} )},
            @{OUName = 'ou=Devices,ou=Computers';      Roles=@( @{Group=$OfficeITTeam;	Permission=@('ComputersCreateDelete','ComputersFullControl')}
                                                                @{Group=$HelpdeskTeam;	Permission=@('ComputersCreateDelete','ComputersFullControl')} )},
            #Group OU
            @{OUName = 'ou=Local,ou=Groups';           Roles=@( @{Group=$OfficeITTeam;	Permission=@('GroupsCreateDelete','GroupsFullControl')}
                                                                @{Group=$HelpdeskTeam;	Permission=@('GroupsCreateDelete','GroupsFullControl')} )},
            @{OUName = 'ou=Standard,ou=Groups';        Roles=@( @{Group=$OfficeITTeam;	Permission=@('GroupsManageMembership','GroupsManager')}
                                                                @{Group=$HelpdeskTeam;	Permission=@('GroupsCreateDelete','GroupsFullControl')} )},
            #Users OU
            @{OUName = 'ou=Disabled,ou=Users';         Roles=@( @{Group=$OfficeITTeam;	Permission=@('None')}
                                                                @{Group=$HelpdeskTeam;	Permission=@('None')} )},
            @{OUName = 'ou=Contacts,ou=Users';         Roles=@( @{Group=$OfficeITTeam;	Permission=@('ContactsCreateDelete','ContactsFullControl')}
                                                                @{Group=$HelpdeskTeam;	Permission=@('ContactsCreateDelete','ContactsFullControl')} )},
            @{OUName = 'ou=Employees,ou=Users';        Roles=@( @{Group=$OfficeITTeam;	Permission=@('UsersEditAttributesGroup1','UsersPasswordandLockout')}
                                                                @{Group=$HelpdeskTeam;	Permission=@('UsersEditAttributesGroup1','UsersPasswordandLockout')} )},
            @{OUName = 'ou=Services,ou=Users';         Roles=@( @{Group=$OfficeITTeam;	Permission=@('UsersEditAttributesGroup1','UsersPasswordandLockout')}
                                                                @{Group=$HelpdeskTeam;	Permission=@('UsersEditAttributesGroup1','UsersPasswordandLockout')} )},
            @{OUName = 'ou=Mailboxes,ou=Users';        Roles=@( @{Group=$OfficeITTeam;	Permission=@('UsersEditAttributesGroup2')}
                                                                @{Group=$HelpdeskTeam;	Permission=@('UsersEditAttributesGroup2','UsersPasswordandLockout')} )}
        )
    }

	#endregion

	#region Create Stucture and Apply Delegations
	        
	# Process OU Structure
    foreach -parallel ($OU in $ConfigurationData.AllNodes) {
        #Each OU will have Roles defined
		$currentOU = $OU.OUName + "," + $BaseOUPath
        Write-Output "Creating OU: " $currentOU
		New-ADOU -Path $currentOU
        Foreach -parallel ($delegation in $ou.Roles) {
            #Each Role will contain one or more Group/Premission sets
            Foreach -parallel ($thisRole in $delegation.Permission) {
                #Each Permission may have one or more ACLs to apply
                $thisOUPath = $OU.ouname + "," + $BaseOUPath 
                $thisDelegate = $delegation.group
                Write-Output "Processing OU: $thisOU  >> Delegating '$thisRole' to '$thisDelegate'"

				switch -CaseSensitive ($thisRole)
				{
					'ComputersCreateDelete'		{ New-ADDelegationComputerObjectsCreateDelete -LDAPPath $thisOUPath -DelegatedAccount $thisDelegate						}
					'ComputersFullControl'		{ New-ADDelegationComputerObjectsFullControl -LDAPPath $thisOUPath -DelegatedAccount $thisDelegate						}
					'GroupsCreateDelete'		{ New-ADDelegationGroupObjectsCreateDelete -LDAPPath $thisOUPath -DelegatedAccount $thisDelegate						}
					'GroupsFullControl'			{ New-ADDelegationGroupObjectsFullControl -LDAPPath $thisOUPath -DelegatedAccount $thisDelegate							} 
					'GroupsManageMembership'	{ New-ADDelegationGroupObjectsMembership -LDAPPath $thisOUPath -DelegatedAccount $thisDelegate							}
					'GroupsManager'				{ New-ADDelegationGroupObjectsManager -LDAPPath $thisOUPath -DelegatedAccount $thisDelegate								}
					'ContactsCreateDelete'		{ New-ADDelegationContactObjectsCreateDelete -LDAPPath $thisOUPath -DelegatedAccount $thisDelegate						}
					'ContactsFullControl'		{ New-ADDelegationContactObjectsFullControl -LDAPPath $thisOUPath -DelegatedAccount $thisDelegate						}
					'UsersEditAttributesGroup1'	{ New-ADDelegationUserObjectsAttributeGroup2 -LDAPPath $thisOUPath -DelegatedAccount $thisDelegate						}
					'UsersEditAttributesGroup2'	{ New-ADDelegationUserObjectsAttributeGroup1 -LDAPPath $thisOUPath -DelegatedAccount $thisDelegate						}
					'UsersPasswordandLockout'	{ New-ADDelegationUserObjectsPasswordandLockout -LDAPPath $thisOUPath -DelegatedAccount $thisDelegate					}
					#default					{ }
				}
            }
        }
    }
          
	#endregion

}

#Sample Call
New-ADOUOfficeBranch -Site "MUM" -BaseOUPath "OU=Office,DC=diginerve,DC=net" -DelegationGroupOUPath "OU=Delegations,DC=diginerve,DC=net"
# Accounts: Administrator account status: disabled
$userAdmin = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq 'Administrator' }
$userAdmin.Disabled = $true
$userAdmin.Put()

# Accounts: Block Microsoft accounts: Users can't add or log on with Microsoft accounts
$regPathBlockMicrosoftAccounts = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions"
Set-ItemProperty -Path $regPathBlockMicrosoftAccounts -Name "SignInOptions_DisableMicrosoftAccount" -Value 1

# Accounts: Guest account status: disabled
$userGuest = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq 'Guest' }
$userGuest.Disabled = $true
$userGuest.Put()

# Accounts: Limit local account use of blank passwords to console logon only: enabled
$regPathLimitBlankPasswords = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $regPathLimitBlankPasswords -Name "LimitBlankPasswordUse" -Value 1

# Audit: Audit access of global system objects: disabled
$regPathAuditGlobalSystemObjects = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
Set-ItemProperty -Path $regPathAuditGlobalSystemObjects -Name "AuditAccessGlobalObjects" -Value 0

# Audit: Audit the use of Backup and Restore privilege: disabled
$regPathAuditBackupRestore = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
Set-ItemProperty -Path $regPathAuditBackupRestore -Name "AuditBackupRestore" -Value 0

# Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings: enabled
$regPathForceAuditPolicy = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
Set-ItemProperty -Path $regPathForceAuditPolicy -Name "SCENoApplyLegacyAuditPolicy" -Value 1

# Audit: Shutdown system immediately if unable to log security audits: enable
$regPathShutdownOnAuditLogFull = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathShutdownOnAuditLogFull -Name "ShutdownWithoutLogon" -Value 1

# DCOM: Machine access restrictions: no remote access for all accounts
$regPathDCOMMachineAccess = "HKLM:\SOFTWARE\Microsoft\OLE"
Set-ItemProperty -Path $regPathDCOMMachineAccess -Name "MachineAccessRestriction" -Value "System"

# DCOM: Machine launch restrictions: no remote launch and remote activation for all accounts
$regPathDCOMMachineLaunch = "HKLM:\SOFTWARE\Microsoft\OLE"
Set-ItemProperty -Path $regPathDCOMMachineLaunch -Name "MachineLaunchRestriction" -Value "System"

# Devices: Allow undock without having to log on: disabled
$regPathAllowUndock = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathAllowUndock -Name "UndockWithoutLogon" -Value 0

# Devices: Allowed to format and eject removable media: administrators and interactive users
$regPathFormatEjectMedia = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Removable"
Set-ItemProperty -Path $regPathFormatEjectMedia -Name "Deny_All" -Value 0

# Devices: Prevent users from installing printer drivers: enabled
$regPathPreventInstallPrinterDrivers = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
Set-ItemProperty -Path $regPathPreventInstallPrinterDrivers -Name "PreventUserOverride" -Value 1

# Domain member: Digitally encrypt or sign secure channel data (always): enabled
$regPathSecureChannelDataAlways = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
Set-ItemProperty -Path $regPathSecureChannelDataAlways -Name "RequireSignOrSeal" -Value 1

# Domain member: Digitally encrypt secure channel data (when possible): enabled
$regPathSecureChannelDataWhenPossible = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
Set-ItemProperty -Path $regPathSecureChannelDataWhenPossible -Name "SealSecureChannel" -Value 1

# Domain member: Digitally sign secure channel data (when possible): enabled
$regPathSignSecureChannelDataWhenPossible = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
Set-ItemProperty -Path $regPathSignSecureChannelDataWhenPossible -Name "SignSecureChannel" -Value 1

# Domain member: Disable machine account password changes: disabled
$regPathDisableMachineAccountPasswordChanges = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
Set-ItemProperty -Path $regPathDisableMachineAccountPasswordChanges -Name "DisablePasswordChange" -Value 0

# Domain member: Maximum machine account password age: 30 days
$regPathMaxMachineAccountPasswordAge = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
Set-ItemProperty -Path $regPathMaxMachineAccountPasswordAge -Name "MaximumPasswordAge" -Value 30

# Domain member: Require strong (Windows 2000 or later) session key: enabled
$regPathRequireStrongSessionKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $regPathRequireStrongSessionKey -Name "RequireStrongKey" -Value 1

# Domain member: Display user information when session is locked: do not display user information
$regPathDisplayUserInformationOnLock = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathDisplayUserInformationOnLock -Name "DontDisplayLockedUserId" -Value 1

# Interactive logon: Do not display last user name: enabled
$regPathDoNotDisplayLastUserName = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathDoNotDisplayLastUserName -Name "DontDisplayLastUserName" -Value 1

# Interactive logon: Do not require CTRL+ALT+DEL: disabled
$regPathDoNotRequireCtrlAltDel = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathDoNotRequireCtrlAltDel -Name "DisableCAD" -Value 0

# Interactive logon: Machine account lockout threshold: 10 invalid logon attempts
$regPathMachineAccountLockoutThreshold = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathMachineAccountLockoutThreshold -Name "InactivityTimeoutSecs" -Value 10

# Interactive logon: Machine inactivity limit: 900 seconds
$regPathMachineInactivityLimit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathMachineInactivityLimit -Name "InactivityTimeoutSecs" -Value 900

# Interactive logon: Number of previous logons to cache (in case domain controller is not available: 4 logons
$regPathNumPreviousLogonsToCache = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathNumPreviousLogonsToCache -Name "CachedLogonsCount" -Value 4

# Interactive logon: Prompt user to change password before expiration: 14 days
$regPathPromptUserToChangePassword = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathPromptUserToChangePassword -Name "InactivityTimeoutSecs" -Value 14

# Interactive logon: Require Domain Controller authentication to unlock workstation: Disabled
$regPathRequireDCAuthToUnlock = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathRequireDCAuthToUnlock -Name "DCUnlock" -Value 0

# Interactive logon: Require smart card: Disabled
$regPathRequireSmartCard = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathRequireSmartCard -Name "ScForceOption" -Value 0

# Interactive logon: Smart card removal behavior: Lock workstation
$regPathSmartCardRemovalBehavior = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathSmartCardRemovalBehavior -Name "ScRemoveOption" -Value 0

# MS network client: Digitally sign communications (always): Enabled
$regPathSignCommAlwaysClient = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
Set-ItemProperty -Path $regPathSignCommAlwaysClient -Name "RequireSecuritySignature" -Value 1

# MS network client: Digitally sign communications (if server agrees): Enabled
$regPathSignCommIfServerAgreesClient = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
Set-ItemProperty -Path $regPathSignCommIfServerAgreesClient -Name "EnableSecuritySignature" -Value 1

# MS network client: Send unencrypted password to third-party SMB servers: Disabled
$regPathSendUnencryptedPassword = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
Set-ItemProperty -Path $regPathSendUnencryptedPassword -Name "EnablePlainTextPassword" -Value 0

# MS network server: Amount of idle time required before suspending session: 15 minutes
$regPathIdleTimeBeforeSuspend = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathIdleTimeBeforeSuspend -Name "InactivityTimeoutSecs" -Value 900

# MS network server: Digitally sign communications (always): Enabled
$regPathSignCommAlwaysServer = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Set-ItemProperty -Path $regPathSignCommAlwaysServer -Name "RequireSecuritySignature" -Value 1

# MS network server: Digitally sign communications (if client agrees): Enabled
$regPathSignCommIfClientAgreesServer = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Set-ItemProperty -Path $regPathSignCommIfClientAgreesServer -Name "EnableSecuritySignature" -Value 1

# MS network server: Disconnect clients when logon hours expire: Enabled
$regPathDisconnectOnLogonHoursExpire = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathDisconnectOnLogonHoursExpire -Name "InactivityTimeoutSecs" -Value 1

# MS network server: Server SPN target name validation level: Accept if provided by client
$regPathSPNValidationLevel = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Set-ItemProperty -Path $regPathSPNValidationLevel -Name "SrvSvcAcceptBothNames" -Value 1

# Network access: Allow anonymous SID/Name translation: Disabled
$regPathAllowAnonSIDTranslation = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $regPathAllowAnonSIDTranslation -Name "RestrictAnonymous" -Value 1

# Network access: Do not allow anonymous enumeration of SAM accounts: Enabled
$regPathNoAnonEnumSAMAccounts = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $regPathNoAnonEnumSAMAccounts -Name "RestrictAnonymousSAM" -Value 1

# Network access: Do not allow anonymous enumeration of SAM accounts and shares: Enabled
$regPathNoAnonEnumSAMAndShares = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Set-ItemProperty -Path $regPathNoAnonEnumSAMAndShares -Name "RestrictNullSessAccess" -Value 1

# Network access: Do not allow storage of passwords and credentials for network authentication: Enabled
$regPathNoStorePasswords = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $regPathNoStorePasswords -Name "NoLMHash" -Value 1

# Network access: Let Everyone permissions apply to anonymous users: Disabled
$regPathEveryonePermissions = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Set-ItemProperty -Path $regPathEveryonePermissions -Name "EveryoneIncludesAnonymous" -Value 0

# Network access: Named Pipes that can be accessed anonymously: Blank (no specific value)
$regPathAnonymousNamedPipes = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Remove-ItemProperty -Path $regPathAnonymousNamedPipes -Name "NullSessionPipes" -ErrorAction SilentlyContinue

# Network access: Remotely accessible registry paths: Blank (no specific value)
$regPathRemotelyAccessibleRegistryPaths = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths"
Remove-Item -Path $regPathRemotelyAccessibleRegistryPaths -ErrorAction SilentlyContinue

# Network access: Remotely accessible registry paths and sub-paths: Blank (no specific value)
$regPathRemotelyAccessibleRegistrySubPaths = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths"
Remove-Item -Path $regPathRemotelyAccessibleRegistrySubPaths -ErrorAction SilentlyContinue

# Network access: Restrict anonymous access to Named Pipes and Shares: Enabled
$regPathRestrictAnonymousAccess = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Set-ItemProperty -Path $regPathRestrictAnonymousAccess -Name "RestrictAnonymous" -Value 1

# Network access: Shares that can be accessed anonymously: Blank (no specific value)
$regPathAnonymousShares = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Remove-ItemProperty -Path $regPathAnonymousShares -Name "NullSessionShares" -ErrorAction SilentlyContinue

# Network access: Sharing and security model for local accounts: Classic - local users authenticate as themselves
$regPathSharingSecurityModel = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Set-ItemProperty -Path $regPathSharingSecurityModel -Name "ForceGuest" -Value 0

# Network security: Allow Local System to use computer identity for NTLM: Enabled
$regPathLocalSystemUseComputerIdentity = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
Set-ItemProperty -Path $regPathLocalSystemUseComputerIdentity -Name "UseMachineId" -Value 1

# Network security: Allow LocalSystem NULL session fallback: Disabled
$regPathLocalSystemNullSessionFallback = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
Set-ItemProperty -Path $regPathLocalSystemNullSessionFallback -Name "AllowNullSessionFallback" -Value 0

# Network security: Allow PKU2U authentication requests to this computer to use online identities: Disabled
$regPathPKU2UAuthentication = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathPKU2UAuthentication -Name "NoConnectedUser" -Value 1

# Network security: Configure encryption types allowed for Kerberos: RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types
$regPathKerberosEncryptionTypes = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
Set-ItemProperty -Path $regPathKerberosEncryptionTypes -Name "SupportedEncryptionTypes" -Value 0x7FFFFFFF

# Network security: Do not store LAN Manager hash value on next password change: Enabled
$regPathDoNotStoreLMHash = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $regPathDoNotStoreLMHash -Name "NoLMHash" -Value 1

# Network security: Force logoff when logon hours expire: Enabled
$regPathForceLogoffOnLogonHoursExpire = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathForceLogoffOnLogonHoursExpire -Name "InactivityTimeoutSecs" -Value 1

# Network security: LAN Manager authentication level: Send NTLMv2 response only, Refuse LM & NTLM
$regPathLANManagerAuthLevel = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $regPathLANManagerAuthLevel -Name "LmCompatibilityLevel" -Value 5

# Network security: LDAP client signing requirements: Negotiate signing
$regPathLDAPClientSigning = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"
Set-ItemProperty -Path $regPathLDAPClientSigning -Name "LDAPClientIntegrity" -Value 1

# Network security: Minimum session security for NTLM SSP based (including secure RPC) clients: Require NTLMv2 session security, Require 128 bit encryption
$regPathNTLMSessionSecurityClients = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
Set-ItemProperty -Path $regPathNTLMSessionSecurityClients -Name "NTLMMinClientSec" -Value 537395200

# Network security: Minimum session security for NTLM SSP based (including secure RPC) server: Require NTLMv2 session security, Require 128 bit encryption
$regPathNTLMSessionSecurityServer = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
Set-ItemProperty -Path $regPathNTLMSessionSecurityServer -Name "NTLMMinServerSec" -Value 537395200

# Network security: Restrict NTLM: Incoming NTLM traffic: Deny all accounts
$regPathRestrictNTLMIncoming = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
Set-ItemProperty -Path $regPathRestrictNTLMIncoming -Name "RestrictReceivingNTLMTraffic" -Value 2

# Network security: Restrict NTLM: NTLM authentication in this domain: Deny all
$regPathRestrictNTLMDomain = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
Set-ItemProperty -Path $regPathRestrictNTLMDomain -Name "RestrictSendingNTLMTraffic" -Value 2

# Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers: Deny all
$regPathRestrictNTLMOutgoing = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
Set-ItemProperty -Path $regPathRestrictNTLMOutgoing -Name "RestrictSendingNTLMTraffic" -Value 2

# Recovery console: Allow automatic administrative logon: Disabled
$regPathRecoveryConsoleAutoLogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
Set-ItemProperty -Path $regPathRecoveryConsoleAutoLogon -Name "SetCommand" -Value ""

# Recovery console: Allow floppy copy and access to all drives and all folders: Disabled
$regPathRecoveryConsoleFloppyAccess = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
Set-ItemProperty -Path $regPathRecoveryConsoleFloppyAccess -Name "SecurityLevel" -Value 4

# Shutdown: Allow system to be shut down without having to logon: Disabled
$regPathShutdownWithoutLogon = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathShutdownWithoutLogon -Name "ShutdownWithoutLogon" -Value 0

# Shutdown: Clear virtual memory page-file: Disabled
$regPathClearPageFileAtShutdown = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
Set-ItemProperty -Path $regPathClearPageFileAtShutdown -Name "ClearPageFileAtShutdown" -Value 0

# System cryptography: Use FIPS compliant algorithms for encryption, hashing and signing: Disabled
$regPathFIPSCompliantAlgorithms = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
Set-ItemProperty -Path $regPathFIPSCompliantAlgorithms -Name "Enabled" -Value 0

# System objects: Require case insensitivity for non-Windows subsystems: Enabled
$regPathCaseInsensitivity = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
Set-ItemProperty -Path $regPathCaseInsensitivity -Name "ObCaseInsensitive" -Value 1

# System objects: Strengthen default permissions of internal system objects (e.g. Symbolic links): Enabled
$regPathStrengthenDefaultPermissions = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
Set-ItemProperty -Path $regPathStrengthenDefaultPermissions -Name "ProtectionMode" -Value 1

# System settings: Optional subsystems: Blank (no specific value)
$regPathOptionalSubsystems = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Subsystems"
Remove-ItemProperty -Path $regPathOptionalSubsystems -Name "Optional" -ErrorAction SilentlyContinue

# System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies: Disabled
$regPathCertificateRules = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer"
Set-ItemProperty -Path $regPathCertificateRules -Name "AuthenticodeEnabled" -Value 0

# UAC: Admin Approval Mode for Built-in Administrator account: Enabled
$regPathAdminApprovalMode = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathAdminApprovalMode -Name "FilterAdministratorToken" -Value 1

# UAC: Allow UIAccess applications to prompt for elevation without using the secure desktop: Disabled
$regPathAllowUIAccessElevation = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathAllowUIAccessElevation -Name "PromptOnSecureDesktop" -Value 0

# UAC: Behavior of elevation prompt for administrators in Admin Approval Mode: Prompt for consent on the secure desktop
$regPathBehaviorAdminPrompt = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathBehaviorAdminPrompt -Name "ConsentPromptBehaviorAdmin" -Value 2

# UAC: Behavior of the elevation prompt for standard users: Automatically deny elevation requests
$regPathBehaviorUserPrompt = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathBehaviorUserPrompt -Name "ConsentPromptBehaviorUser" -Value 0

# UAC: Detect application installations and prompt for elevation: Enabled
$regPathDetectAppInstallPrompt = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathDetectAppInstallPrompt -Name "EnableInstallerDetection" -Value 1

# UAC: Only elevate executables that are signed and validated: Disabled
$regPathElevateSignedExecutables = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathElevateSignedExecutables -Name "ValidateAdminCodeSignatures" -Value 0

# UAC: Only elevate UIAccess applications that are installed in secure locations: Enabled
$regPathElevateSecureLocations = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathElevateSecureLocations -Name "EnableSecureUIAPaths" -Value 1

# UAC: Run all administrators in Admin Approval Mode: Enabled
$regPathRunAdminInApprovalMode = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathRunAdminInApprovalMode -Name "EnableLUA" -Value 1

# UAC: Switch to the secure desktop when prompting for elevation: Enabled
$regPathSecureDesktopPrompt = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathSecureDesktopPrompt -Name "PromptOnSecureDesktop" -Value 1

# UAC: Virtualize file and registry write failures to per-user locations: Enabled
$regPathVirtualizeFailures = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPathVirtualizeFailures -Name "EnableVirtualization" -Value 1

Write-Host "Configuration tasks completed."

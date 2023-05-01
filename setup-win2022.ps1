<# Init Log #>;
Start-Transcript -Path 'C:/Setup/kopicloud-ad-api-setup-log.txt' -append;
<#$DebugPreference = 'Continue' #>;
$VerbosePreference = 'Continue';
$InformationPreference = 'Continue';

<# Variables #>;
$website = "API";
$admin_password = "K0p1Cl0ud";
$apiusername = "KopiCloudSvc";
$apipassword = "K0p1Cl0ud";
$codefolder = "C:\KopiCloud-AD-API";

<# Set Temp Variable #>;
New-Item -Path "C:\TEMP" -Type Directory;
[System.Environment]::SetEnvironmentVariable('TEMP','C:\TEMP', 'Machine');
[System.Environment]::SetEnvironmentVariable('TMP','C:\TEMP', 'Machine');

<# Set Drive Name #>;
Set-Volume -DriveLetter C -NewFileSystemLabel "KopiCloud-AD-API";

<# Enable Windows Event Log #>;
$LogName = "KopiCloud AD API";
New-EventLog -source $LogName -LogName $LogName;
Write-EventLog -LogName $LogName -Source $LogName -EventID 1 -EntryType Information -Message "Event Log Source [KopiCloud AD API] Started";

<# Install Dependencies #>;
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force;
Enable-WindowsOptionalFeature -Online -FeatureName NetFx4Extended-ASPNET45;

<# Install DNS Management #>;
Install-WindowsFeature RSAT-DNS-Server;

<# Set Local Administrator Password #>;
Write-Host "# Set Local Administrator Password #";
net user Administrator $admin_password;
wmic useraccount where "name='Administrator'" set PasswordExpires=FALSE;

<# Creating the Service Account User #>;
Write-Host "# Creating the APISVC User #";
$password = ConvertTo-SecureString $apipassword -AsPlainText -Force;
New-LocalUser -Name $apiusername -Password $password -FullName $apiusername -Description "KopiCloud AD API Service Account";

<# Add APISVC User to Local Administrator Group #>;
Add-LocalGroupMember -Group "Administrators" -Member $apiusername;

<# Create folders for the website #>; 
if (!(test-path $codefolder)) { New-Item -Path $codefolder -ItemType Directory };

<# Assign Permissions to the Website Folder #>; 
$acl = Get-ACL -Path $codefolder;
$AccessRule1 = New-Object System.Security.AccessControl.FileSystemAccessRule($apiusername,"FullControl","ContainerInherit,ObjectInherit","None","Allow");
$acl.SetAccessRule($AccessRule1);
$iisuser = "IIS_IUSRS";
$AccessRule2 = New-Object System.Security.AccessControl.FileSystemAccessRule($iisuser,"FullControl","ContainerInherit,ObjectInherit","None","Allow");
$acl.SetAccessRule($AccessRule2);
$acl | Set-Acl -Path $codefolder;

<# Download API Code #>;
$Version = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/KopiCloud-AD-API-Setup/Setup-Files/main/release.version';
$Url = 'https://github.com/KopiCloud-AD-API-Setup/Setup-Files/releases/download/' + $Version.Content.Trim() + '/KopiCloud-AD-API.zip';
$destination = "$env:TEMP\KopiCloud-AD-API.zip";
Invoke-WebRequest -Uri $Url -OutFile $destination;

<# Decompress API Code #>;
Expand-Archive -Path $destination -DestinationPath $codefolder -Force;

<# Install IIS #>;
Install-WindowsFeature -Name web-server -IncludeManagementTools;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationDevelopment;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationInit;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIExtensions;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIFilter;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebSockets;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-NetFxExtensibility45;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASP;

<# Remove Default Web Site #>;
Remove-IISSite "Default Web Site" -Confirm:$false;

<# Create the IIS Pool and WebSite #>;
New-WebAppPool $website;
New-Item IIS:\Sites\API -Bindings @{protocol="http";bindingInformation="*:80:"} -PhysicalPath $codefolder;
Set-ItemProperty IIS:\Sites\$website -Name applicationpool -Value $website;
Set-ItemProperty IIS:\AppPools\$website -Name processModel -Value @{username=$apiusername;password=$apipassword;identitytype=3};
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='$website']/application[@path='/']/virtualDirectory[@path='/']" -name "userName" -value $apiusername;
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='$website']/application[@path='/']/virtualDirectory[@path='/']" -name "password" -value $apipassword;

<# Download .NET Core 6 #>; 
$source = "https://download.visualstudio.microsoft.com/download/pr/7ab0bc25-5b00-42c3-b7cc-bb8e08f05135/91528a790a28c1f0fe39845decf40e10/dotnet-hosting-6.0.16-win.exe";
$destination = "$env:TEMP\net6.exe";
Invoke-WebRequest -Uri $source -OutFile $destination;

<# Install .NET Core 6 #>; 
Start-Process -FilePath $destination -Args "/install /quiet /norestart" -Verb RunAs -Wait;

<## Generate Self-Signing Certificate #>;
$machine = [System.Net.Dns]::GetHostName();
$certThumbprint = New-SelfSignedCertificate -DnsName $machine -CertStoreLocation "cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(5);

<# Configure IIS to use HTTPS #>;
New-WebBinding -Name $website -Protocol "https";
$api = Get-WebBinding -Name $website;
$api.AddSslCertificate($certThumbprint.Thumbprint, "My");

<# Download Rewrite URL #>;
$source = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi";
$destination = "$env:TEMP\rewrite.msi";
Invoke-WebRequest -Uri $source -OutFile $destination;

<# Install RewriteURL #>;
$MSIArguments = "/i $destination /quiet";
Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow;

<# Create Rewrite URL Rule to Enforce HTTPS #>;
$rulename = $website + ' http to https';
$inbound = '(.*)';
$outbound = 'https://{HTTP_HOST}{REQUEST_URI}';
$site = 'IIS:\Sites\' + $website;
$root = 'system.webServer/rewrite/rules';
$filter = "{0}/rule[@name='{1}']" -f $root, $rulename;
Add-WebConfigurationProperty -PSPath $site -filter $root -name '.' -value @{name=$rulename; patterSyntax='Regular Expressions'; stopProcessing='True'};
Set-WebConfigurationProperty -PSPath $site -filter "$filter/match" -name 'url' -value $inbound;
Set-WebConfigurationProperty -PSPath $site -filter "$filter/conditions" -name '.' -value @{input='{HTTPS}'; matchType='0'; pattern='^OFF$'; ignoreCase='True'; negate='False'};
Set-WebConfigurationProperty -PSPath $site -filter "$filter/action" -name 'type' -value 'Redirect';
Set-WebConfigurationProperty -PSPath $site -filter "$filter/action" -name 'url' -value $outbound;

<# DISABLED
Install SQL Server Management Studio
Write-Host "# Install SQL Server Management Studio #";
$Path = $env:TEMP;
$Installer = "SSMS-Setup-ENU.exe";
$URL = "https://aka.ms/ssmsfullsetup";
Invoke-WebRequest $URL -OutFile $Path\$Installer;
Start-Process -FilePath $Path\$Installer -Args "/install /quiet" -Verb RunAs -Wait;
Remove-Item $Path\$Installer;
DISABLED #>;
 
<# Install SQL Server Express 2022 #>;
Write-Host "# Install SQL Server Express 2022 #";
$instance = "MSSQLSERVER";
$SQLMedia = "C:\SQLMedia";
$SQLData = "C:\SQLData";
$SQLBackup = "C:\SQLData\Backup";
$Path = $env:TEMP;
$Installer = "SQL2022-SSEI-Expr.exe";
$SQLInstaller = "SQLEXPR_x64_ENU.exe";
$URL = "https://download.microsoft.com/download/5/1/4/5145fe04-4d30-4b85-b0d1-39533663a2f1/SQL2022-SSEI-Expr.exe";
Invoke-WebRequest $URL -OutFile $Path\$Installer;
Start-Process -FilePath $Path\$Installer -Args "/ACTION=Download /MEDIAPATH=$Path /QUIET" -Verb RunAs -Wait;
Start-Process -FilePath $Path\$SQLInstaller -Args "/x:$SQLMedia /q" -Verb RunAs -Wait;
Start-Process -FilePath "$SQLMedia\SETUP.EXE" -Args "/ACTION=INSTALL /FEATURES=SQL /INSTANCENAME=$instance /IACCEPTSQLSERVERLICENSETERMS /INSTALLSQLDATADIR=$SQLData /SQLBACKUPDIR=$SQLBackup /q" -Verb RunAs -Wait;
Remove-Item $Path\$Installer;

<# Configure the SQL Server Authentication #>;
Write-Host "Configure the SQL Server Authentication";
Install-Module sqlserver -AllowClobber -force;
Import-Module sqlserver;
$sqlinstance = $env:ComputerName;
$server = New-Object Microsoft.SqlServer.Management.Smo.Server $sqlinstance;
$server.Settings.LoginMode = 'Mixed';
$server.Alter();
Get-Service -Name 'MSSQLSERVER' | Restart-Service -Force;

<# Create Login #>;
$login = New-Object ('Microsoft.SqlServer.Management.Smo.Login') $instance, $apiusername;
$login.LoginType = 'SqlLogin';
$login.PasswordPolicyEnforced = $false;
$login.PasswordExpirationEnabled = $false;
$login.Create($apipassword);

<# Grant Sysadmin Permissions #>;
$sysadminRole = $server.Roles['sysadmin'];
$sysadminRole.AddMember($apiusername);
$sysadminRole.Alter();

<# Create Login for SQL DB Access User #>;
$sqluserDB = "KopiCloudAPI";
$sqluserPassword = "K0p1Cl0ud";
$loginDB = New-Object ('Microsoft.SqlServer.Management.Smo.Login') $instance, $sqluserDB;
$loginDB.LoginType = 'SqlLogin';
$loginDB.PasswordPolicyEnforced = $false;
$loginDB.PasswordExpirationEnabled = $false;
$loginDB.Create($sqluserPassword);

<# Grant Sysadmin Permissions to SQL DB Access User #>;
$sysadminRoleDB = $server.Roles['sysadmin'];
$sysadminRoleDB.AddMember($sqluserDB);
$sysadminRoleDB.Alter();

<# Download the API Config Tool #>;
Write-Host "# Download the API Config Tool #";
$configfolder = "C:\KopiCloud-AD-API-Config";
if (!(test-path $configfolder)) { New-Item -Path $configfolder -ItemType Directory };
$URL = "https://github.com/KopiCloud-AD-API-Setup/launch-config/releases/download/v1.0.0/LaunchConfig.exe";
Invoke-WebRequest $URL -OutFile ($configfolder + "\LaunchConfig.exe");

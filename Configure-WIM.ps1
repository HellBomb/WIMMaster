#Requires -Version 5.0
Param (
    [String]$Iso      = "C:\Elevation\SW_DVD9_Win_Server_STD_CORE_2016_64Bit_English_-4_DC_STD_MLF_X21-70526.ISO",
    [String]$FinalWim = "",
    [Switch]$CreateConfigFile,
    [Switch]$OverwriteWIM
)

Begin {
    #------------------------------------------------------------[Functions]----------------------------------------------------------
    Function Write-nLog {
    <#
        .SYNOPSIS
            Standardized & Easy to use logging function.
        .DESCRIPTION
            Easy and highly functional logging function that can be dropped into any script to add logging capability without hindering script performance.
        .PARAMETER type
            Set the event level of the log event. 
            [Options]
                Info, Warning, Error, Debug
        
        .PARAMETER message
            Set the message text for the event.
        .PARAMETER ErrorCode
            Set the Error code for Error & fatal level events. The error code will be displayed in front of 
            the message text for the event.
        .PARAMETER WriteHost
            Force writing to host reguardless of SetWriteLog setting for this specific instance.
        .PARAMETER WriteLog
            Force writing to log reguardless of SetWriteLog setting for this specific instance.
        .PARAMETER SetLogLevel
            Set the log level for the nLog function for all future calls. When setting a log level all logs at 
            the defined level will be logged. If you set the log level to warning (default) warning messages 
            and all events above that such as error and fatal will also be logged. 
            (1) Debug: Used to document events & actions within the script at a very detailed level. This level 
            is normally used during script debugging or development and is rarely set once a script is put into
            production
            (2) Information: Used to document normal application behavior and milestones that may be useful to 
            keep track of such. (Ex. File(s) have been created/removed, script completed successfully, etc)
            (3) Warning: Used to document events that should be reviewed or might indicate there is possibly
            unwanted behavior occuring.
            (4) Error: Used to document non-fatal errors indicating something within the script has failed.
            (5) Fatal: Used to document errors significant enough that the script cannot continue. When fatal
            errors are called with this function the script will terminate. 
        
            [Options]
                1,2,3,4,5
        .PARAMETER SetLogFile
            Set the fully quallified path to the log file you want used. If not defined, the log will use the 
            "$Env:SystemDrive\ProgramData\Scripts\Logs" directory and will name the log file the same as the 
            script name. 
        .PARAMETER SetWriteHost
            Configure if the script should write events to the screen. (Default: $False)
            [Options]
                $True,$False
        
        .PARAMETER SetWriteLog
            Configure if the script should write events to the screen. (Default: $True)
            [Options]
                $True,$False
        
        .INPUTS
            None
        .OUTPUTS
            None
        .NOTES
        VERSION     DATE			NAME						DESCRIPTION
	    ___________________________________________________________________________________________________________
	    1.0         25 May 2020		HellBomb					Initial version
        Credits:
            (1) Script Template: https://gist.github.com/9to5IT/9620683
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [ValidateSet('Debug','Info','Warning','Error','Fatal')]
        [String]$Type,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False,Position=1)]
        [String[]]$Message,
        [Parameter(Mandatory=$False,ValueFromPipeline=$False,Position=2)][ValidateRange(0,9999)]
        [Int]$ErrorCode,
        
        #Trigger per-call write-host/write-log 
        [Switch]$WriteHost,
        [Switch]$WriteLog,

        #Variables used to trigger setting global variables.
        [Switch]$Initialize,
        [Parameter(Mandatory=$False,ValueFromPipeline=$False)][ValidateRange(1,5)]
        [Int]$SetLogLevel,
        [Parameter(Mandatory=$False,ValueFromPipeline=$False)][ValidateScript({Test-Path $_})]
        [String]$SetLogFile,
        [Parameter(Mandatory=$False,ValueFromPipeline=$False)]
        [Bool]$SetWriteHost,
        [Parameter(Mandatory=$False,ValueFromPipeline=$False)]
        [Bool]$SetWriteLog
    )

    Begin {
        #Get Timestamp from when nLog was called.
        [DateTime]$tTimeStamp = [DateTime]::Now
        [Bool]$tLog = $False

        #Ensure all the default script-level variables are set.
        IF ((-Not (Test-Path variable:Script:nLogInitialize)) -OR $Initialize) {
            New-Variable -Name nLogLevel -Value 3 -Scope Script -Force
            New-Variable -Name nLogInitialize -Value $True -Force -ErrorAction SilentlyContinue -Scope Script
            IF (Test-Path variable:global:psISE) {
                New-Variable -Name nLogWriteHost -Value $True  -Scope Script -Force
                New-Variable -Name nLogWriteLog  -Value $False -Scope Script -Force
            } Else {
                New-Variable -Name nLogWriteHost -Value $False -Scope Script -Force
                New-Variable -Name nLogWriteLog  -Value $True  -Scope Script -Force
            }
            If ([String]::IsNullOrEmpty([io.path]::GetFileNameWithoutExtension($script:MyInvocation.MyCommand.path))) {
                New-Variable -Name nLogFile -Scope Script -Force -Value "$env:ALLUSERSPROFILE\Scripts\Logs\ISETestScript.log"
            } Else {
                New-Variable -Name nLogFile -Scope Script -Force -Value "$env:ALLUSERSPROFILE\Script\Logs\$([io.path]::GetFileNameWithoutExtension($script:MyInvocation.MyCommand.path))`.log"
            }
        }

        #Initalize of the variables.
        IF ($PSBoundParameters.ContainsKey('SetLogLevel')) {
            Set-Variable -Name nLogLevel -Value $SetLogLevel -Force -Scope Script
        }
        IF ($PSBoundParameters.ContainsKey('SetWriteHost')) {
            Set-Variable -Name nLogWriteHost -Value $SetWriteHost -Force -Scope Script
        }
        IF ($PSBoundParameters.ContainsKey('SetWriteLog')) {
            Set-Variable -Name nLogWriteLog -Value $SetWriteLog -Force -Scope Script
        }
        IF ($PSBoundParameters.ContainsKey('SetLogFile')) {
            Set-Variable -Name nLogWriteLog -Value $SetLogFile -Force -Scope Script
        }

        #Determine log level
        Switch ($Type) {
            {$Type -eq 'Debug'   -AND $Script:nLogLevel -EQ 1} {$tLevel = "[DEBUG]`t`t"; $tForeGroundColor = "Cyan"   ; $tLog = $True; $tErrorString = [String]::Empty }
            {$Type -eq 'Info'    -AND $Script:nLogLevel -LE 2} {$tLevel = "[INFO]`t`t" ; $tForeGroundColor = "White"  ; $tLog = $True; $tErrorString = [String]::Empty }
            {$Type -eq 'Warning' -AND $Script:nLogLevel -LE 3} {$tLevel = "[WARNING]`t"; $tForeGroundColor = "DarkRed"; $tLog = $True; $tErrorString = [String]::Empty }
            {$Type -eq 'Error'   -AND $Script:nLogLevel -LE 4} {$tLevel = "[ERROR]`t`t"; $tForeGroundColor = "Red"    ; $tLog = $True; $tErrorString = "[$($ErrorCode.ToString("0000"))] " }
            {$Type -eq 'Fatal'   -AND $Script:nLogLevel -LE 5} {$tLevel = "[FATAL]`t`t"; $tForeGroundColor = "Red"    ; $tLog = $True; $tErrorString = "[$($ErrorCode.ToString("0000"))] " }
        }

        #Determine what we should be logging/writing. 
        IF ($WriteHost) { $tWriteHost = $True } Else { $tWriteHost = $Script:nLogWriteHost } 
        IF ($WriteLog)  { $tWriteLog  = $True } Else { $tWriteLog  = $Script:nLogWriteLog  }

        $tTimeStampString = $tTimeStamp.ToString("yyyy-mm-dd hh:mm:ss")
        
        #Ensure we have the timestamp of last entry for debug time differences
        IF (-Not (Test-Path variable:Script:nLogLastTimeStamp)) {
            New-Variable -Name nLogLastTimeStamp -Value $tTimeStamp -Scope Script -Force
        }

        #Calculate the time difference 
        $tDifference = " ($(((New-TimeSpan -Start $Script:nLogLastTimeStamp -End $tTimeStamp).Seconds).ToString(`"0000`"))`s)"

        if ($tWriteLog -and $tLog) {
            If (![System.IO.File]::Exists($Script:nLogFile)) {
                New-Item -Path (Split-path $Script:nLogFile -Parent) -Name (Split-path $Script:nLogFile -Leaf) -Force -ErrorAction Stop
            }
            $tLogWriter = [System.IO.StreamWriter]::New($Script:nLogFile,"Append")
        }
    }

    Process {
        IF ($tLog) {
            IF ($tWriteHost) { 
                Write-Host "$tTimeStampString$tDifference`t$tErrorString$Message" -ForegroundColor $tForeGroundColor
            }
        
            IF ($tWriteLog)  {
                $LogWriter.WriteLine("$tTimeStampString$tDifference`t$tErrorCode$Message")
            }
            #Ensure we have the timestamp of the last log execution.
            Set-Variable -Name nLogLastTimeStamp -Scope Script -Value $tTimeStamp -Force
        }
    }

    End {
        if ($tWriteLog -and $tLog) {
            $tLogWriter.Flush()
            $tLogWriter.Close()
        }

        #Cleanup Used Variables to make ISE development more consistent. 
        Get-Variable -Name * -Scope Local |Where-Object { (@("WriteHost","WriteLog","Type","tTimeStampString","tTimeStamp","tLog","TerminatingError","tDifference","SetLogLevel","SetLogFile","ErrorCode","Message","Initialize","SetWriteHost","SetWriteLog","tWriteLog","tWriteHost","tLogWriter") -contains $_.Name) } |Remove-Variable
        
        #Allow us to exit the script from the logging function.
        If ($Type -eq 'Fatal') {
            Exit
        }
    }

}
    Function Get-ScriptDirectory {
        $Invocation = ((Get-Variable MyInvocation -Scope Script).Value).MyCommand.path
        If ([String]::IsNullOrWhiteSpace($Invocation)) {
            #Document is not being run from a saved document, reverting to $temp dir
            $Result = $env:TEMP
        } Else {
            $Result = Split-Path -Parent -Path $Invocation
        }
        Return $Result
    }
    Function Get-ShortestString {
        Param (
            $Array
        )
        #Find Starting Commong String to automatically generate XML file name.
        $xmlsettings = New-Object System.Xml.XmlWriterSettings
        $xmlsettings.Indent = $true
        $xmlsettings.IndentChars = "    "

        [int]$Char = 0
        $Stop = $false
        While ($char -LE $Array[0].Length -AND $Stop -NE $True) {
            For ($i=0; $i -lt $Array.count; $i++) {
                IF ($Array[$I][$Char] -ne $Array[0][$char]) {
                    $Stop = $True
                }
            }
            $Char++
        }

        Return $Array[0].substring(0,$char-1).Trim()
    }

    #----------------------------------------------------------[Prerequisites]---------------------------------------------------------
    Write-nLog -Initialize Debug -Message "Initializing nLog"
    $ScriptDir  = Get-ScriptDirectory
    
    #Used to detect if script is being run in powershell ISE. If it is, simulate actions instead of taking them.
    $ISEDebug = Test-Path variable:global:psISE

    #Ensure Script is Running as Administrator (1)
    If (!$ISEDebug) {
        $IsAdmin=[Security.Principal.WindowsIdentity]::GetCurrent()
        If ((New-Object Security.Principal.WindowsPrincipal $IsAdmin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $FALSE) {
            Write-nLog -Message "You are NOT a local administrator.  Run this script after logging on with a local administrator account." -WriteHost
            Exit 1
        }
    }

    If ($ISEDebug) {
        #If running in Powershell ISE ask if script should run as administrator
        Write-host "Would you like to run script with debugging disabled? (Default is No)" -ForegroundColor Yellow
        $Readhost = Read-Host " ( y / n ) " 
        Switch ($ReadHost) { 
            Y       { Write-host "Yes, Run script without '-whatif' flags."; $Debug=$False } 
            N       { Write-Host "No, Skip PublishSettings";                 $Debug=$True  } 
            Default { Write-Host "Default, Skip PublishSettings";            $Debug=$True  } 
        }

        If ($Debug) {
            Write-nLog -SetLogLevel 1 -SetWriteHost $True -SetWriteLog $FALSE -Type Debug -Message "Debugging enabled"
            $OverwriteWIM = $True
        }
    }

    #Ensure the ISO file exists and is readable.
    Try {
        IF ([System.IO.File]::OpenRead($ISO).CanRead -eq $True) {
            Write-nLog -Type Debug -Message "Successfully able to read `$ISO."
        } Else {
            Write-nLog -Type Warning -Message "Most likely unable to read `$ISO."
        }
    } Catch {
        Write-nLog -Type Fatal -Message "Unable to validate `$ISO file."
    }

    #Find Directory we have read/write permissions too.
    ForEach ($Dir in @($FinalWIM,$ScriptDir,$env:TEMP)) {
        Try {
            New-Item -Path (Split-Path $Dir -Parent) -Name ([System.Guid]::NewGuid()) -Force -ErrorAction Stop |Remove-Item -Force -ErrorAction Stop
            $OutDir = $Dir
            Write-nLog -Type Debug -Message "Outdir configured: $OutDir"
            Break;
        } Catch {
            Write-nLog -Type Info -Message "Directory not Read & Writeable: $Dir"
        }
    }

    #Mount ISO and copy WIM file.
    Try {
        Write-nLog -Type Debug -Message "Attempting to mount windows ISO. ($ISO)"
        $DiskImage = Mount-DiskImage -ImagePath $ISO -ErrorAction Stop
        $ISOVolume = $DiskImage |Get-Volume
        Write-nLog -Type Info -Message "Successfully mounted windows ISO. ($ISO)"
    } Catch {
        Write-nLog -Type Fatal -Message "Failed to mount windows ISO. ($ISO)"
    }

    #Determine which WIM files we need.
    IF ($CreateConfigFile) { 
        $WIMS = Get-ChildItem -Path "$($ISOVolume.DriveLetter):\Sources\" |Where-Object {$_.Name -match "(install)" -AND $_.extension -match "(wim|esd)"}
    } Else {
        $WIMS = Get-ChildItem -Path "$($ISOVolume.DriveLetter):\Sources\" |Where-Object {$_.Name -match "(install|boot)" -AND $_.extension -match "(wim|esd)"}
    }

    #Copy needed WIM files from source to destination.
    ForEach ($WIM in $WIMS) {
        New-Variable -Name "$($WIM.BaseName)WIM" -Value "$OutDir\$($WIM.name)" -ErrorAction Stop -Force

        Try {
            IF ([System.IO.File]::Exists("$OutDir\$($WIM.name)") -AND $OverwriteWIM -EQ $False) {
                Write-nLog -Type Info -Message "Existing $($_.name) already exists in output and `$OverwriteWIM set to `$False. Renaming existing file to $($WIM.BaseName)$(([DateTime]::Now).ToString("hh-mm-tt-ddMMMyy"))$($_.extension)"
                Rename-Item -Path "$OutDir\$($_.name)" -NewName "$($WIM.BaseName)$(([DateTime]::Now).ToString("hh-mm-tt-ddMMMyy"))$($WIM.extension)"
            } Else {
                Write-nLog -Type Info -Message "Existing $($WIM.name) already exists in output and `$OverwriteWIM set to `$True so overwriting existing file. "
            }
        } Catch {
            Write-nLog -Type Error -Message "Unable to rename '$($WIM.name)' to '$($WIM.BaseName)$(([DateTime]::Now).ToString("hh-mm-tt-ddMMMyy"))$($WIM.extension)'."
        }

        Try {
            Write-nLog -Type Debug -Message "Attempting to copy $($WIM.name). (Source: $($WIM.FullName) (Desination: $OutDir\$($WIM.name))"
            Copy-Item -Path $WIM.FullName -Destination "$OutDir\$($WIM.name)" -ErrorAction Stop -Force -PassThru | Set-ItemProperty -name IsReadOnly -Value $FALSE -Force
            Write-nLog -Type Info -Message "Successfully copied $($WIM.name) to working directory."
        } Catch {
            Write-nLog -Type Fatal -Message "Failed to copy $($WIM.name) to working directory. (Source: $($WIM.FullName) (Desination: $OutDir\$($WIM.name))"
        }
    }
    
    $XMLPath   = "$OutDir\$((Get-ShortestString -Array (Get-WindowsImage -ImagePath $InstallWIM |foreach {$_.ImageName})).replace(' ','_'))`.xml"
    IF ([String]::IsNullOrEmpty($XMLPath)) {
        Write-nLog -Type Fatal -Message "unable to determine XML file name"
    }
}

Process {
    Try {
        Write-nLog -Type Debug -Message "Attempting to create mountdir."
        $MountDir = (New-Item -ItemType Directory -Path (Join-Path $Env:Temp ([System.Guid]::NewGuid()))).fullname
        Write-nLog -Type Info -Message "Successfully created temporary WIM mount directory. ($MountDir)"
    } Catch {
        Write-nLog -Type Error -Message "Failed to create MountDir."
    }

    IF ($CreateConfigFile) {
        Mount-WindowsImage -Path $MountDir -Index 1 -ImagePath $InstallWIM -ReadOnly |Out-Null
        
        #Create Basic Folder structure
        Write-nLog -Type Info -Message "Creating required directories."
        $RequiredFolders = @("$OutDir\Drivers","$OutDir\Updates","$OutDir\Updates\ServicingStackUpdates","$OutDir\Updates\CumulativeUpdates")
        ForEach ($Folder in $RequiredFolders) {
            IF ([System.IO.Directory]::Exists($Folder)) {
                Write-nLog -Type debug -Message "Directory already exists. Directory$Folder"
            } Else {
                Try {
                    Write-nLog -Type Info -Message "Creating new $([System.io.path]::GetDirectoryName($Folder)) directory. "
                    New-Item -Path $Folder -ItemType Directory -Force -OutVariable $Null
                    Write-nLog -Type Debug -Message "Successfully created new directory. (Directory: $Folder)"
                } Catch {
                    Write-nLog -Type Warning -Message "Failed to create new directory. (Directory: $Folder)"
                }
            }
        }


        $XmlWriterSettings = New-Object System.Xml.XmlWriterSettings
        $XmlWriterSettings.Indent = $True
        $XmlWriterSettings.IndentChars = "    "

        # Set the File Name Create The Document
        $XmlWriter = [System.XML.XmlWriter]::Create($XMLPath, $XmlWriterSettings)

        # Write the XML Decleration and set the XSL
        $xmlWriter.WriteStartDocument()

        # Start the Root Element
        $xmlWriter.WriteStartElement("WIMMaster")

            #Script Config
            $xmlWriter.WriteStartElement("ScriptConfig")
                $xmlWriter.WriteStartElement("WindowsOptionalFeature")
                    $xmlWriter.WriteAttributeString("Skip","$False")
                $XmlWriter.WriteEndElement() #</WindowsOptionalFeature>

                $xmlWriter.WriteStartElement("WindowsCapability")
                    $xmlWriter.WriteAttributeString("Skip","$False")
                $XmlWriter.WriteEndElement() #</WindowsCapability>

                $xmlWriter.WriteStartElement("ImageProcessing")
                    $xmlWriter.WriteAttributeString("OptimizeImage" ,"$True")
                    $xmlWriter.WriteAttributeString("RepairImage"   ,"$True")
                    $xmlWriter.WriteAttributeString("ImportUpdates" ,"$True")
                    $xmlWriter.WriteAttributeString("ImportDrivers" ,"$True")
                $XmlWriter.WriteEndElement() #</ImageProcessing>

            $xmlWriter.WriteEndElement() #</ScriptConfig>


            $xmlWriter.WriteStartElement("WindowsImage")
                ForEach ($Index in (Get-WindowsImage -ImagePath $InstallWIM)) {
                    $xmlWriter.WriteStartElement("index")
                        $xmlWriter.WriteAttributeString("Index",$Index.ImageIndex)
                        $xmlWriter.WriteAttributeString("ImageName",$Index.ImageName)
                        $xmlWriter.WriteAttributeString("Remove","$False")
                    $XmlWriter.WriteEndElement() #</Index>
                }
            $xmlWriter.WriteEndElement() #</WindowsImage>


            $xmlWriter.WriteStartElement("WindowsOptionalFeature")
                ForEach ($Feature in (Get-WindowsOptionalFeature -Path $MountDir)) {
                    $xmlWriter.WriteStartElement("Feature")
                        $xmlWriter.WriteAttributeString("FeatureName",$Feature.FeatureName)
                        $xmlWriter.WriteAttributeString("State",$Feature.State)
                        $xmlWriter.WriteAttributeString("DefaultState",$Feature.State)
                    $XmlWriter.WriteEndElement() #</Feature>
                }
            $xmlWriter.WriteEndElement() #</WindowsOptionalFeature>


            $xmlWriter.WriteStartElement("WindowsCapability")
                ForEach ($Capability in (Get-WindowsCapability -Path $MountDir| Where-Object {$_.State -eq "Installed"})) {
                    $xmlWriter.WriteStartElement("Capability")
                        $xmlWriter.WriteAttributeString("FeatureName",$Capability.Name)
                        $xmlWriter.WriteAttributeString("Remove","$False")
                    $XmlWriter.WriteEndElement() #</Capability>
                }
            $xmlWriter.WriteEndElement() #</WindowsCapability>

        $xmlWriter.WriteEndElement() # <-- End <WIMMaster> 

        # End, Finalize and close the XML Document
        $xmlWriter.WriteEndDocument()
        $xmlWriter.Flush()
        $xmlWriter.Close()

        Dismount-WindowsImage -Path $MountDir -Discard  |Out-Null

    } Else { #End CreateConfigFile
        IF ([System.IO.File]::Exists($XMLPath)) {
            Try {
                [XML]$XMLFile   = Get-Content $XMLPath
                If ([String]::IsNullOrEmpty($XMLPath)) {
                    Write-nLog -Type Error -Message "XML file is empty. (File: $XMLPath)"
                } Else {
                    Write-nLog -Type Debug -Message "Successfully read contents of XML config file (File: $XMLPath)"
                }

            } Catch {
                Write-nLog -Type Error -Message "XML file located, but unable to read file. (File: $XMLPath)"
            }
        } Else {
            Write-nLog -Type Fatal -Message "Required XML file does not exist. (File: $XMLPath)"
        }
        $WIMImages = Get-WindowsImage -ImagePath $InstallWIM

        ForEach ($Index in $WIMImages) {
            IF ($XMLFile.WIMMaster.WindowsImage.index.Where({$_.ImageName -eq $Index.ImageName -AND $_.remove -eq $True})) {
                Try {
                    Remove-WindowsImage -ImagePath $InstallWIM -Name $Index.ImageName |Out-Null
                    Write-nLog -Type Info -Message "Successfully removed image. ($($Index.ImageName))"
                    Continue
                } Catch {
                    Write-nLog -Type Error -Message "Failed to remove image. ($($Index.ImageName))"
                }
            }

            #Mount the WIM file
            Try {
                Mount-WindowsImage -Path $MountDir -ImagePath $InstallWIM -Name $Index.ImageName -ErrorAction Stop |Out-Null
                Write-nLog -Type Info -Message "Successfully Mounted Image. (Image Name: $($Index.imageName))"
                Write-nLog -Type Debug -Message "Successfully Mounted Image. (ImageName: $($Index.imageName)) (ImagePath: $InstallWIM) (Path: '$MountDir')"
            } Catch {
                Write-nLog -Type Warning -Message "Failed to mount image. (Index: $($Index.imageName)) (ImagePath: $InstallWIM) (Path: '$MountDir')"
            }

            #Configure Optional Features
            IF ($XMLFile.WIMMaster.ScriptConfig.WindowsOptionalFeature.Skip -eq "False") {
                $XMLFile.WIMMaster.WindowsOptionalFeature.Feature.Where({$_.State -NE $_.DefaultState}) |ForEach-Object {
                    Try {
                        IF ($_.state -eq "Enabled") {
                            Enable-WindowsOptionalFeature -FeatureName $_.FeatureName -Path $MountDir -ErrorAction Stop |Out-Null
                        } ElseIF ($_.state -eq "Disabled") {
                            Disable-WindowsOptionalFeature -FeatureName $_.FeatureName -Path $MountDir -ErrorAction Stop |Out-Null
                        } Else {
                            Write-nLog -Type Warning -Message "Invalid setting of '$($_.State)' was configured for '$($_.FeatureName)"
                        }
                        Write-nLog -Type Info -Message "Successfully set '$($_.FeatureName)' to '$($_.State)'."
                    }  Catch {
                        Write-nLog -Type Error -Message "Failed to set '$($_.FeatureName)' to '$($_.State)'."
                    }
                }
            }
            
            #Configure Capabilities
            IF ($XMLFile.WIMMaster.ScriptConfig.WindowsCapability.Skip -eq "False") {
                $XMLFile.WIMMaster.WindowsCapability.Capability.Where({$_.Remove -EQ "True"}) |ForEach-Object {
                    Try {
                        Remove-WindowsCapability -Name $_.FeatureName -Path $MountDir -ErrorAction Stop |Out-Null
                        Write-nLog -Type Info -Message "Successfully Removed Windows Capability.  ($($_.FeatureName))"
                    } Catch {
                        Write-nLog -Type Error -Message "Failed to Remove Windows Capability. ($($_.FeatureName).)"
                    }
                }
            }
            
            #Apply Updates
            IF ($XMLFile.WIMMaster.ScriptConfig.ImageProcessing.ImportUpdates -eq "True") {
                If ([System.IO.Directory]::Exists("$ScriptDir\ServicingStackUpdates")) {
                    Write-nLog -Type Info -Message "Importing Servicing Stack Updates"
                    Get-ChildItem -Path "$ScriptDir\ServicingStackUpdates" -Recurse |Where {$_.Extension -match "msu|cab"} |ForEach-Object {
                        Add-WindowsPackage -PackagePath $_.FullName -Path $MountDir
                    }
                    If ([System.IO.Directory]::Exists("$ScriptDir\Updates")) {
                        Write-nLog -Type Info -Message "Importing Updates"
                        Get-ChildItem -Path "$ScriptDir\Updates" -Recurse |Where {$_.Extension -match "msu|cab"} |ForEach-Object {
                            Add-WindowsPackage -PackagePath $_.FullName -Path $MountDir
                        }
                    } Else {
                        Write-nLog -Type Warning -Message "Unable to locate Servicing Stack Updates folder. (Directory: $ScriptDir\ServicingStackUpdates)"
                    }
                } Else {
                    Write-nLog -Type Warning -Message "Unable to locate Servicing Stack Updates folder. (Directory: $ScriptDir\ServicingStackUpdates)"
                }
            }

            IF ($XMLFile.WIMMaster.ScriptConfig.ImageProcessing.ImportDrivers -eq "True") {
                If ([System.IO.Directory]::Exists("$ScriptDir\Drivers")) {
                    Write-nLog -Type Info -Message "Importing Drivers"
                    Add-WindowsDriver -Recurse -Driver "$ScriptDir\Drivers" -Path $MountDir
                } Else {
                    Write-nLog -Type Warning -Message "Unable to locate drivers folder. (Directory: $ScriptDir\Updates)"
                }
                If ([System.IO.Directory]::Exists("$ScriptDir\Drivers")) {
                    Write-nLog -Type Info -Message "Importing Drivers"
                    Add-WindowsDriver -Recurse -Driver "$ScriptDir\Drivers" -Path $MountDir
                } Else {
                    Write-nLog -Type Warning -Message "Unable to locate drivers folder. (Directory: $ScriptDir\Updates)"
                }
            }

            #Dismount InstallWIM file
            Try {
                Dismount-WindowsImage -Save -Path $MountDir |Out-Null
                Write-nLog -Type Info -Message "Successfully dismounted image. ($($Index.ImageName))"
            } Catch {
                Write-nLog -Type Fatal -Message "Failed to dismount image. ($($Index.ImageName))"
            }
        }

        #Mount BootWIM and inject Drivers
        Try {
            Mount-WindowsImage -Path $MountDir -ImagePath $BootWIM -Name $Index.ImageName -ErrorAction Stop |Out-Null
            Write-nLog -Type Info -Message "Successfully Mounted Image. (Image Name: $($Index.imageName))"
            Write-nLog -Type Debug -Message "Successfully Mounted Image. (ImageName: $($Index.imageName)) (ImagePath: $BootWIM) (Path: '$MountDir')"
        } Catch {
            Write-nLog -Type Warning -Message "Failed to mount image. (Index: $($Index.imageName)) (ImagePath: $BootWIM) (Path: '$MountDir')"
        }

        IF ($XMLFile.WIMMaster.ScriptConfig.ImageProcessing.ImportDrivers -eq "True") {
            If ([System.IO.Directory]::Exists("$ScriptDir\Drivers")) {
                Write-nLog -Type Info -Message "Importing Drivers"
                Add-WindowsDriver -Recurse -Driver "$ScriptDir\Drivers" -Path $MountDir
            } Else {
                Write-nLog -Type Warning -Message "Unable to locate drivers folder. (Directory: $ScriptDir\Updates)"
            }
            If ([System.IO.Directory]::Exists("$ScriptDir\Drivers")) {
                Write-nLog -Type Info -Message "Importing Drivers"
                Add-WindowsDriver -Recurse -Driver "$ScriptDir\Drivers" -Path $MountDir
            } Else {
                Write-nLog -Type Warning -Message "Unable to locate drivers folder. (Directory: $ScriptDir\Updates)"
            }
        }

        Try {
            Dismount-WindowsImage -Save -Path $MountDir |Out-Null
            Write-nLog -Type Info -Message "Successfully dismounted image. ($($Index.ImageName))"
        } Catch {
            Write-nLog -Type Fatal -Message "Failed to dismount image. ($($Index.ImageName))"
        }

    }
}

End {
    #Dismount ISO now that we are done copying needed files from it.
    Write-nLog -Type Info -Message "Dismounting `$ISO"
    $Dismount = Dismount-DiskImage $ISO
    While ([String]::IsNullOrEmpty($Dismount) -eq $False) {
        $Dismount = Dismount-DiskImage $ISO
    }

    $RemoveVariables = @(
        #Parameters
        "Iso","FinalWim"

        #Begin
        "ScriptDir","ISEDebug","IsAdmin","Readhost","Dir","OutDir","DiskImage","ISOVolume","WIMFile","WIMS","WIM","installWIM","BootWIM","XMLPath"

        #Process
        "XmlWriterSettings","xmlWriter","MountDir","XMLFile","WIMImages",

        #End
        "Dismount"
    )
    Get-Variable -Name * -Scope Local |Where-Object { ($RemoveVariables -contains $_.Name) } |Remove-Variable
}

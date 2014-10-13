Function New-VMReferenceImage {
    param (
        [string]$VMName = "REF_2012R2_RTM_G1",
        [string]$VMPath = "V:\Resources\Pool 1\Resources\",
        [string]$SourceVHD = "V:\Resources\Pool 1\Parents\REF_2012R2_RTM_G1.vhdx",
        [string]$VSwith = "Corpnet01",
        [string]$VMVLanID = 110,
        [switch]$PrepareNow
    )

    begin {
        $VHDPath = $VMPath + $VMName
        if(!(Test-Path -path "$VHDPath")) 
        { 
            New-Item -ItemType directory -Path $VHDPath -force | Out-Null  
        } 
    }
    process
    {
        $Release = Get-Date -Format yyyyMM
        $ReferenceVHDName = $VMPath + $VMName + '\' + $VMName + '_' + $Release + ".vhdx"
        Write-Progress "Create Reference Image" "Cloning VHD $SourceVHD to $ReferenceVHDName" -id 0 -percentComplete 10
          
        copy $SourceVHD $ReferenceVHDName -Force

        Write-Progress "Create Reference Image" "Creating Virtual Machine $VMName" -id 0 -percentComplete 30  
        New-VM -Name $VMName -MemoryStartupBytes 512Mb -NoVHD -Generation 1 -SwitchName $VSwith -Path $VMPath -Verbose
        Set-VM -Name $VMName -ProcessorCount 2 -DynamicMemory:$True -MemoryMinimumBytes 512Mb -MemoryMaximumBytes 2048Mb -AutomaticStopAction TurnOff -Verbose
        Set-VMNetworkAdapterVlan -VMName $VMName -Access -VlanId $VMVLanID
        
        Write-Progress "Create Reference Image" "Adding Virtual Disk $ReferenceVHDName to VM $VMName" -id 0 -percentComplete 50
        Add-VMHardDiskDrive -VMName $VMName -ControllerType IDE -ControllerNumber 0 -Path $ReferenceVHDName

        Get-VM $VMName -Verbose| Enable-VMResourceMetering -Verbose

        if ($PrepareNow) {
            Write-Progress "Create Reference Image" "Starting VM $VMName" -id 0 -percentComplete 60
            Start-VM -Name $VMName

            #Wait for the VM to be turned off
            do {
                Write-Progress "Create Reference Image" "Waiting for VM $VMName to Power Off" -id 0 -percentComplete 75
                Start-Sleep -s 10
            } until ((get-vm $VMName).state -eq "Off")

            #Compress the new VHD
            Write-Progress "Create Reference Image" "Compressing VHD $ReferenceVHDName" -id 0 -percentComplete 85
            Compress-DiskImage -VHDFile $ReferenceVHDName
        }
        Write-Progress "Create Reference Image" "Completed Creation of VHD $ReferenceVHDName" -id 0 -percentComplete 100
    }
}


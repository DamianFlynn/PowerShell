Function Compress-DiskImage {
    param (
        [string]$VHDFile
    )

    process {
        Write-Progress "Compress-DiskImage" "Calculating Current Metrics for $VHDFile" -id 1 -percentComplete 10
        $FileSizeStart = Get-ChildItem $VHDFile | select length

        Write-Progress "Compress-DiskImage - Pass 1" "Mounting Virtual Hard Disk $VHDFile in Read and Write Mode" -id 1 -percentComplete 10
        $before = (Get-Volume).DriveLetter
        Mount-DiskImage -ImagePath $VHDFile
        $after = (Get-Volume).DriveLetter
        $driveLetter = compare $before $after -Passthru
        $driveLetter = $driveLetter +  ":\"

        Write-Progress "Compress-DiskImage" "Using DISM to Clean Up Windows Components in $VHDFile" -id 1 -percentComplete 20
        DISM /Image:$driveLetter /Cleanup-Image /StartComponentCleanup /ResetBase

        Write-Progress "Compress-DiskImage - Pass 1" "Defragmenting VHD $VHDFile mounted as $driveletter" -id 1 -percentComplete 30
        defrag $driveletter /U /V /X

        Write-Progress "Compress-DiskImage - Pass 1" "Mounting Virtual Hard Disk $VHDFile in Read Only Mode" -id 1 -percentComplete 40            
        Dismount-DiskImage -ImagePath $VHDFile -Verbose
        $VHDData = Mount-DiskImage -ImagePath $VHDFile -Access ReadOnly -PassThru

        Write-Progress "Compress-DiskImage - Pass 1" "Optimizing VHD $VHDFile mounted as $driveletter" -id 1 -percentComplete 50
        $FileSizePass1 = $VHDData.FileSize
        Optimize-VHD -Path $VHDFile -Mode Full
        Dismount-DiskImage -ImagePath $VHDFile -Verbose

        Write-Progress "Compress-DiskImage - Pass 2" "Mounting Virtual Hard Disk $VHDFile in Read and Write Mode" -id 1 -percentComplete 60
        $before = (Get-Volume).DriveLetter
        Mount-DiskImage -ImagePath $VHDFile
        $after = (Get-Volume).DriveLetter
        $driveLetter = compare $before $after -Passthru
        $driveLetter = $driveLetter +  ":\"

        Write-Progress "Compress-DiskImage - Pass 2" "Defragmenting VHD $VHDFile mounted as $driveletter" -id 1 -percentComplete 70
        defrag $driveletter /U /V /X
        
        Write-Progress "Compress-DiskImage - Pass 2" "Mounting Virtual Hard Disk $VHDFile in Read Only Mode" -id 1 -percentComplete 80                
        Dismount-DiskImage -ImagePath $VHDFile -Verbose
        $VHDData = Mount-DiskImage -ImagePath $VHDFile -Access ReadOnly -PassThru
        $FileSizePass2 = $VHDData.FileSize

        Write-Progress "Compress-DiskImage - Pass 2" "Optimizing VHD $VHDFile mounted as $driveletter" -id 1 -percentComplete 90
        Optimize-VHD -Path $VHDFile -Mode Full
        Dismount-DiskImage -ImagePath $VHDFile -Verbose

        Write-Progress "Compress-DiskImage" "Completed Compress Procedure for VHD $VHDFile" -id 1 -percentComplete 100
        $FileSizeEnd = Get-ChildItem $VHDFile | select length

        New-Object PSObject -Property @{ 
            FileName = $VHDFile
            InitialFileSize = $FileSizeStart.Length
            OptimizedFileSize = $FileSizeEnd.Length
        } 
    }
}     


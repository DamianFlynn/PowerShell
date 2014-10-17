#
# Create-SMARecurringSchedules.ps1
#


function ADD-SMARecurringSchedule {
    param (
        $RecurringInterval = 30,
        $ScheduleNamePrefix = "Execute Flow at ",
        $WebServiceEndpoint
    )

    process {
        $iterations = 1440 / $interval
        $endDate   = Get-Date -Month 12 -Day 31 -year 9999 -Hour 5 -Minute 00 -second 00
        $StartDateUTC = Get-Date -Hour 00 -Minute 00 -Second 00
        $StartDateEST = Get-Date -Hour 04 -Minute 00 -Second 00
        $endDate   = Get-Date -Month 12 -Day 31 -year 9999 -Hour 5 -Minute 00 -second 00

        foreach ($iteration in 0..$iterations) {
            $dateString = get-date $StartDateEST  -Format HH:mm
            $Name = "$ScheduleNamePrefix $dateString"
            Write-Output $Name
            Set-SmaSchedule -StartTime $StartDateUTC -ExpiryTime $endDate -Name $Name -ScheduleType "DailySchedule" -dayInterval 1 -WebServiceEndpoint $WebServiceEndpoint
    
            $StartDateEST = $StartDateEST.AddMinutes($interval)
            $StartDateUTC = $StartDateUTC.AddMinutes($interval)
        }
    }
}


function ADD-SMARunbookRecurringSchedule {
    param (
        $RecurringInterval = 30,
        $RunbookName,
		$ScheduleNamePrefix = "Execute Flow at",
        $WebServiceEndpoint
    )

    process {
        $iterations = 1440 / $RecurringInterval
        $StartDateUTC = Get-Date -Hour 00 -Minute 00 -Second 00
        foreach ($iteration in 0..$iterations) {
            $dateString = get-date $StartDateUTC  -Format HH:mm
            $Name = "$ScheduleNamePrefix $dateString"
            Write-Output $Name
            Start-SMARunbook -Name $RunbookName -webserviceendpoint $WebServiceEndpoint -schedulename $Name
            $StartDateUTC = $StartDateUTC.AddMinutes($RecurringInterval)
        }
    }
}

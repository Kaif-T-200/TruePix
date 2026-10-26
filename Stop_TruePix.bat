@echo off
powershell -NoProfile -Command "$procs = Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'python*.exe' -and ($_.CommandLine -like '*streamlit run app.py*') }; if($procs){ $procs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }; Write-Host 'TruePix stopped successfully.' } else { Write-Host 'No running TruePix process found.' }"
pause

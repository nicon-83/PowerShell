Function PcInfo {

    <#
    .SYNOPSIS
        Выводит информацию о компьютере
    .DESCRIPTION
        Данная функция выводит информацию о компьютере (Имя компьютера, Версия ОС, Архитектура ОС, Версия сборки ОС, IP адресс, MAC адрес)
    .EXAMPLE
        PcInfo
        Выведет информацию о локальном компьютере
    .EXAMPLE
        PcInfo -ComputerName "Win10"
        Выведет информацию об удаленном компьютере с именем "Win10"
    .PARAMETER ComputerName
        Имя или ip-адрес компьютера (необязательный параметр, если не указан, то по умолчанию выводится информация о локальном ПК)
    #>
    param (
        [PARAMETER(Mandatory=$False,Position=0)][String]$ComputerName='localhost'
    )

    $Computer = Get-WmiObject win32_operatingsystem -ComputerName $ComputerName

    $info = @()

    if($Computer){
        $CSName = $Computer.CSName
        $Caption = $Computer.Caption
        $OsArchitecture = $Computer.OsArchitecture
        $BuildNumber = $Computer.BuildNumber
        $NetCard = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $ComputerName | where {$_.IPAddress -like '*10.80.*'}
        $MACAddress = $NetCard.MACAddress
        $IPAddress = $NetCard.IPAddress[0]

        if($BuildNumber -eq '10240'){
               $BuildNumber = 'initial version'
        }
        if($BuildNumber -eq '10586'){
               $BuildNumber = '1511'
        }
        if($BuildNumber -eq '14393'){
               $BuildNumber = '1607'
        }
        if($BuildNumber -eq '15063'){
               $BuildNumber = '1703'
        }
        if($BuildNumber -eq '16299'){
               $BuildNumber = '1709'
        }

        #Write-Host "$CSName / $Caption / $OsArchitecture / $BuildNumber / $IPAddress / $MACAddress" -ForegroundColor DarkYellow

        $info += New-Object PsObject -Property @{Имя=$CSName; Версия=$Caption; Разрядность=$OsArchitecture; Сборка=$BuildNumber; IPAddress=$IPAddress; MAC=$MACAddress}

        $info

    } else {
        Write-Host "В сети не найден ПК с именем $ComputerName, попробуйте ввести полное имя ПК" -ForegroundColor Red
    }
}


Function RemoteOn {

    <#
    .SYNOPSIS
        Запуск команды Enable-PSRemoting на удаленном компьютере
    .DESCRIPTION
        Данная функция запускает на удаленном компьютере команду powershell "Enable-PSRemoting"
    .EXAMPLE
        RemoteOn-ComputerName "Win10"
        Запускает на удаленном компьютере с именем "win10" команду powershell "Enable-PSRemoting"
    .PARAMETER ComputerName
        Имя или ip-адрес удаленного компьютера (обязательный параметр)
    #>
    param (
        [PARAMETER(Mandatory=$True,Position=0)][String]$ComputerName
    )

    $WinRm = Get-Service -ComputerName $ComputerName -Name winrm -ErrorAction SilentlyContinue

    if( ($WinRm) -and ($WinRm.Status -ne "Running") ){
       $WinRm.start()
       Write-Host "Служба WinRm успешно запущена" -ForegroundColor Green
    } elseif ( ($WinRm) -and ($WinRm.Status -eq "Running") ){
        Write-Host "Служба WinRm уже запущена" -ForegroundColor Green
    } else {
        Write-Host "ПК $ComputerName нет в сети" -ForegroundColor Red
        return
    }

    Start-Process PsExec.exe -ArgumentList "\\$ComputerName -s C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe Enable-PSRemoting -force"
    Write-Host "Удаленное управление на компьютере $ComputerName включено" -ForegroundColor Green
}


Function Get-MsiSoft {
     
    <#
    .SYNOPSIS
        Выводит список установленных на компьютере пакетов Msi
    .DESCRIPTION
        Данная функция выводит список всех установленных на компьютере пакетов Msi, если указано название конкретной программы, то производит поиск пакета по указанному имени.
    .EXAMPLE
        Get-MsiSoft
        Выведет список установленных пакетов Msi на локальном компьютере
    .EXAMPLE
        Get-MsiSoft -ComputerName "Win10"
        Выведет список установленных пакетов Msi на удаленном компьютере с именем "Win10"
    .EXAMPLE
        Get-MsiSoft -ComputerName Win10 -SoftName "7zip"
        Выведет список установленных пакетов Msi на удаленном компьютере с именем "Win10" в названии которых содержится строка "7Zip"
    .PARAMETER ComputerName
        Имя или ip-адрес компьютера (необязательный параметр, если не указан, то по умолчанию поиск производится на локальном ПК)
    .PARAMETER SoftName
        Название программы которую необходимо найти (необязательный параметр, если не указан, будет выведен список всех программ)
    #>
    param (
        [PARAMETER(Mandatory=$False,Position=0)][String]$ComputerName='localhost',
        [PARAMETER(Mandatory=$False,Position=1)][String]$SoftName
    )

    if (Test-Connection $ComputerName -Count 2 -Quiet) {

        if ($SoftName) {

            $soft = Get-WmiObject win32_product -ComputerName $ComputerName | where Name -Like "*$SoftName*" | select Name, Version, InstallDate | ft -AutoSize
            if ($soft) {
                $soft
            } else {
                Write-Host "На компьютере $ComputerName не найдено приложений с именем $SoftName, попробуйте указать более точное имя приложения." -ForegroundColor Red
            }

        } else {

            Get-WmiObject win32_product -ComputerName $ComputerName | select Name, Version, InstallDate | ft -AutoSize
        
        }

    } else {
            Write-Host ""
            Write-Host "В сети не найден компьютер с именем $ComputerName, возможно неверно указано Имя или ПК выключен." -ForegroundColor Red
    }
}


Function Rm-MsiSoft {

    <#
    .SYNOPSIS
        удаление пакетов Msi на компьтере
    .DESCRIPTION
        Данная функция удаляет указанный Msi пакет с компьютера
    .EXAMPLE
        Rm-MsiSoft "chrome"
        Удалит с локального компьютера пакет msi в имени которого содержится строка "chrome"
    .EXAMPLE
        Rm-MsiSoft -ComputerName Win10 -SoftName "chrome"
        Удалит с компьютера с именем "Win10" пакет msi в имени которого содержится строка "chrome"
    .PARAMETER ComputerName
        Имя или ip-адрес компьютера (необязательный параметр, если не указан, то по умолчанию поиск производится на локальном ПК)
    .PARAMETER SoftName
        Название программы которую необходимо найти (обязательный параметр), если в имени удаляемого приложения имеются пробелы, то имя заключаем в кавычки
    #>
    param (
        [PARAMETER(Mandatory=$False,Position=0)][String]$ComputerName='localhost',
        [PARAMETER(Mandatory=$True,Position=1)][String]$SoftName
    )
        
    if (Test-Connection $ComputerName -Count 2 -Quiet) {

        $Soft = Get-WmiObject win32_product -ComputerName $ComputerName | where Name -like "*$SoftName*"
        $count = $Soft.count

        if($Soft){
            if(!$count){
                $name = $Soft.Name
                $result = $Soft.Uninstall()
                if($result.ReturnValue -eq 0){
                    Write-Host ""
                    Write-Host "Приложение $name успешно удалено с ПК $ComputerName" -ForegroundColor Green
                } elseif ($result.ReturnValue -eq 3010) {
                    Write-Host ""
                    Write-Host "Для завершения удаления приложения $name необходимо перезагрузить компьютер $ComputerName" -ForegroundColor DarkYellow
                    $result
                    Write-Host "см. коды ошибок на https://msdn.microsoft.com/en-us/library/aa390890(v=vs.85).aspx"
                } else {
                    Write-Host ""
                    Write-Host "Произошла ошибка при удалении приложения $name." -ForegroundColor Red
                    $result
                    Write-Host "см. коды ошибок на https://msdn.microsoft.com/en-us/library/aa390890(v=vs.85).aspx"
                }
            } else {
                Write-Host ""
                Write-Host "Найдено $count приложения(й) с именем $SoftName, укажите более точное имя приложения." -ForegroundColor Red
            }
        } else {
            Write-Host ""
            Write-Host "Приложение с именем $SoftName на ПК $ComputerName не найдено." -ForegroundColor Red
        }
    } else {
            Write-Host ""
            Write-Host "В сети не найден ПК с именем $ComputerName, возможно неверно указано имя или ПК выключен." -ForegroundColor Red
    }
}


Function Install-Msi {

    <#
    .SYNOPSIS
        Удаленная установка пакетов msi на компьютер пользователя домена
    .DESCRIPTION
        Данная функция позволяет удаленно установить пакет msi на компьютер пользователя домена, установка программ из сети не поддерживается, т.к. в домене на компьютерах отключено делегирование.
    .EXAMPLE
        Install-Msi "win10" "c:\distr\GoogleChrome.msi"
        На компьютер с именем "win10" будет удаленно установлен пакет GoogleChrome.msi
    .PARAMETER ComputerName
        полное Имя или ip-адрес компьютера
    .PARAMETER SoftPath
        полный путь к устанавливаемому пакету, если в пути содержаться пробелы - заключаем в кавычки
    #>
    param (
        [PARAMETER(Mandatory=$True,Position=0)][String]$ComputerName,
        [PARAMETER(Mandatory=$True,Position=1)][String]$SoftPath
    )

    $result = (Get-WMIObject -ComputerName $ComputerName -List | Where-Object -FilterScript {$_.Name -eq "Win32_Product"}).Install("$SoftPath")

    if($result.ReturnValue -eq 0){
        Write-Host "Приложение $SoftPath успешно установлено" -ForegroundColor Green
    } else {
        Write-Host "Ошибка при установке приложения $SoftPath" -ForegroundColor Red
        $result = $result.ReturnValue
        Write-Host "Код ошибки $result"
        Write-Host "см. коды ошибок на https://msdn.microsoft.com/en-us/library/aa390890(v=vs.85).aspx"
    }
   
}


Function Get-ExeSoft {

    <#
    .SYNOPSIS
        Выводит список установленных на компьютере программ по информации из веток реестра HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall,
        HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall
    .DESCRIPTION
        Данная функция выводит список всех установленных на компьютере программ, если указано название конкретной программы, то производит поиск пакета по указанному имени.
    .EXAMPLE
        Get-ExeSoft
        Выведет список установленных программ на локальном компьютере
    .EXAMPLE
        Get-MsiSoft -ComputerName "Win10"
        Выведет список установленных программ на удаленном компьютере с именем "Win10"
    .EXAMPLE
        Get-MsiSoft -ComputerName Win10 -SoftName "7zip"
        Выведет список установленных программ на удаленном компьютере с именем "Win10" в названии которых содержится строка "7Zip"
    .PARAMETER ComputerName
        Имя или ip-адрес компьютера (необязательный параметр, если не указан, то по умолчанию поиск производится на локальном ПК)
    .PARAMETER SoftName
        Название программы которую необходимо найти (необязательный параметр, если не указан, будет выведен список всех программ)
    #>
    param (
        [PARAMETER(Mandatory=$False,Position=0)][String]$ComputerName='localhost',
        [PARAMETER(Mandatory=$False,Position=1)][String]$SoftName
    )

    if (Test-Connection $ComputerName -Count 2 -Quiet) {

        $OsArchitecture = (Get-WmiObject win32_operatingsystem -ComputerName $ComputerName | select -Property *).OsArchitecture

        if($OsArchitecture -like "*64*"){

            $soft = Invoke-Command -ComputerName $ComputerName {
                Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall
            }

        } else {
    
            $soft = Invoke-Command -ComputerName $ComputerName {
                Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
            }

        }

        if($SoftName){

            $soft = $soft | Get-ItemProperty -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like "*$SoftName*"} #| `
            #Select-Object -Property DisplayName, UninstallString, QuietUninstallString | fl
            if($soft){

                $soft | foreach {
                    $_
                    $UninstallString = $_.UninstallString
                    if($UninstallString){
                        Write-Host "Строка для удаления:" -ForegroundColor DarkYellow
                        Write-Host "-----------------------------------------------------------------------" -ForegroundColor Green
                        $UninstallString
                        Write-Host "Example: MsiExec.exe /uninstall {AC76BA86-7AD7-1049-7B44-AB0000000001} /quiet /norestart"
                        Write-Host "-----------------------------------------------------------------------" -ForegroundColor Green
                        Write-Host ""
                    } else {
                        $soft = $_.DisplayName
                        Write-Host "Для приложения $soft не найдена строка для удаления" -ForegroundColor Red
                    }
                }

            } else {
            
                Write-Host "На компьютере $ComputerName не найдено приложений с именем $SoftName, попробуйте указать более точное имя приложения." -ForegroundColor Red
            
            }

        } else {
        
            $soft | Get-ItemProperty -ErrorAction SilentlyContinue | Select-Object -Property DisplayName, UninstallString, QuietUninstallString | fl
        
        }

    } else {
    
        Write-Host ""
        Write-Host "В сети не найден компьютер с именем $ComputerName, возможно неверно указано Имя или ПК выключен." -ForegroundColor Red
    
    }
}


Function User {

    <#
    .SYNOPSIS
        вывод информации об учетной записи пользователя домена
    .DESCRIPTION
        Данная функция выводит информацию об учетной записи пользователя домена
    .EXAMPLE
        User "иванов"
        Выведет информацию об учетных записях пользователей в имени которых встречается строка "иванов"
    .PARAMETER UserName
        полное имя пользователя или несколько символов имени
    #>
    param (
        [PARAMETER(Mandatory=$True,Position=0)][String]$UserName
    )
    
    $User = Get-ADUser -Filter "CN -like '*$UserName*'" -Properties logoncount, BadLogonCount, badPwdCount, Created, PasswordLastSet, PasswordExpired, Department, Description, ipphone, LastBadPasswordAttempt, mobilephone, Manager, Title
    if($User){
        $User
    } else {
        Write-Host "В домене не найден пользователем с именем $UserName" -ForegroundColor Red
    }
}


Function UserPass {

    <#
    .SYNOPSIS
        вывод информации о состоянии пароля учетной записи пользователя домена
    .DESCRIPTION
        Данная функция выводит информацию о состоянии пароля учетной записи пользователя домена
    .EXAMPLE
        UserPass "иванов"
        Выведет информацию о паролях пользователей в имени которых встречается строка "иванов"
    .PARAMETER UserName
        полное имя пользователя или несколько символов имени
    #>
    param (
        [PARAMETER(Mandatory=$True,Position=0)][String]$UserName
    )

    $User =  Get-ADUser -Filter "CN -like '*$UserName*'" -Properties CN, AccountLockoutTime, BadLogonCount, badPwdCount, Created, PasswordLastSet, PasswordExpired
    if($User){
        $User
    } else {
        Write-Host "В домене не найден пользователем с именем $UserName" -ForegroundColor Red
    }
}


Function UserPC {

    <#
    .SYNOPSIS
        поиск компьютера на котором залогинен пользователь
    .DESCRIPTION
        Данная функция выполняет поиск компьютера на котором залогинен пользователь (зеленый - ПК в сети, серый ПК не в сети)
    .EXAMPLE
        UserPC "иванов"
        Выведет список компьютеров, на которых залогинены пользователи в имени которых встречается строка "иванов"
    .PARAMETER UserName
        полное имя пользователя или несколько символов имени
    #>
    param (
        [PARAMETER(Mandatory=$True,Position=0)][String]$UserName
    )

    $UserComputer = Get-ADComputer -Filter "Description -like '*$UserName*'" -Properties Description, IPv4Address

    if($UserComputer){
    
        $UserComputer | ForEach-Object {
        
            $name = $_.Description
            $user = Get-ADUser -Filter "name -like '$name'" -Properties *
            $ipphone = $user.ipphone
            $position = $user.title
            $mobile = $user.mobilephone
            $department = $user.description
    
            if(Test-Connection $_.Name -Count 2 -Quiet) {
                Write-Host $_.Name.toUpper() `t $_.IPv4Address `t $_.Description `t $ipphone `t $position `t $department `t $mobile -ForegroundColor Green
                Write-Host ""
            }else{
                Write-Host $_.Name.toUpper() `t $_.IPv4Address `t $_.Description `t $ipphone `t $position `t $department `t $mobile -ForegroundColor Gray
                Write-Host ""
            }
        }
    } else {
        Write-Host "Не найден компьютер с пользователем по имени $UserName" -ForegroundColor Red
    }
}


Function FindPC {

    <#
    .SYNOPSIS
        Поиск полного серийного номера ПК по нескольким символам
    .DESCRIPTION
        Данная функция выполняет поиск полного серийного номера ПК по нескольким символам
    .EXAMPLE
        FindPC "win10"
        Выведет список компьютеров, в названии которых встречается строка "win10"
    .PARAMETER ComputerName
        Полное Имя или ip-адрес компьютера или несколько символов имени
    #>
    param (
        [PARAMETER(Mandatory=$True,Position=0)][String]$ComputerName
    )

    $Computer = Get-ADComputer -Filter "Name -like '*$ComputerName*'"
        
    if($Computer){

        $Computer | ForEach-Object {

            $comp = Get-ADComputer -Identity $_.Name -Properties *
            if(Test-Connection $_.Name -Count 2 -Quiet){
                Write-Host $_.Name.ToUpper() `t $comp.Description `t "LastLogonDate:"$comp.LastLogonDate -ForegroundColor Green
            } else {
                Write-Host $_.Name.ToUpper() `t $comp.Description `t "LastLogonDate:"$comp.LastLogonDate -ForegroundColor Gray
            }

        }
    } else {
        Write-Host "Не найден компьютер с именем $ComputerName" -ForegroundColor Red
    }
}


Function UserGroup {

    <#
    .SYNOPSIS
        Выводит группы в которые входит учетная запись пользователя
    .DESCRIPTION
        Данная функция выводит список групп, в которые входит учетная запись пользователя
    .EXAMPLE
        UserGroup "иванов"
        Выведет список групп в которые входит учетная запись, в названии которой встречается строка "Иванов"
    .PARAMETER UserName
        Имя учетной записи, для которой необходимо вывести группы
    #>
    param (
        [PARAMETER(Mandatory=$True,Position=0)][String]$UserName
    )

    $User = Get-ADUser -Filter "CN -like '*$UserName*'"

    if($User) {
        
        $User | ForEach-Object {

            $GroupsNames = @()
            $UserLogin = $_.SamAccountName
            Write-Host "-------------------------------------"
            Write-Host $_.Name -ForegroundColor Green
            Write-Host "-------------------------------------"
            $Group = Get-ADPrincipalGroupMembership $UserLogin
            $GroupName = $Group | Sort-Object | select -ExpandProperty name
            $GroupName | foreach {
            
                $Gr = Get-ADGroup -Filter "name -like '$_'" -Properties Description
                $GroupsNames += New-Object PsObject -Property @{Name=$Gr.Name;Description=$Gr.Description}

            }

            $GroupsNames | ft -AutoSize

        }

    } else {
        Write-Host "Не найден пользователь с именем $UserName" -ForegroundColor Red
    }
}


Function GroupDescription {

    <#
    .SYNOPSIS
        Выводит описание группы
    .DESCRIPTION
        Данная функция выводит информацию из поля 'Description' указанной группы
    .EXAMPLE
        GroupDescription 'Domain Users'
        Выведет описание группы 'Domain Users'
    .PARAMETER GroupName
        Имя группы
    #>
    param (
        [PARAMETER(Mandatory=$True,Position=0)][string]$GroupName
    )

    $Group = Get-ADGroup -Filter "name -like '*$GroupName*'" -Properties *
    if($Group){

        $Group | foreach {
            Write-Host ""
            Write-Host $_.Name ":" $_.Description -ForegroundColor DarkYellow
            Write-Host ""
        }
    } else {
        Write-Host "Не найдена группа с именем $GroupName" -ForegroundColor Red
    }

}


Function RemoteCmd {

        <#
    .SYNOPSIS
        Устанавливает интерактивную сессию с удаленным компьютеров
    .DESCRIPTION
        Данная функция в режиме командной строки создает интерактивную сессию с удаленным компьютеров посредством утилиты psexec.exe
    .EXAMPLE
        RemoteCmd "win10"
        Будет создана интерактивная сессия в режиме командной строки с удаленным компьютером "win10"
    .PARAMETER ComputerName
        имя компьютера
    #>
    param (
        [PARAMETER(Mandatory=$True,Position=0)][String]$ComputerName
    )

    Start-Process psexec.exe -ArgumentList "\\$ComputerName cmd -i"

}


function Test-Port{  
<#    
.SYNOPSIS    
    Tests port on computer.  
    
.DESCRIPTION  
    Tests port on computer. 
     
.PARAMETER computer  
    Name of server to test the port connection on.
      
.PARAMETER port  
    Port to test 
       
.PARAMETER tcp  
    Use tcp port 
      
.PARAMETER udp  
    Use udp port  
     
.PARAMETER UDPTimeOut 
    Sets a timeout for UDP port query. (In milliseconds, Default is 1000)  
      
.PARAMETER TCPTimeOut 
    Sets a timeout for TCP port query. (In milliseconds, Default is 1000)
                 
.NOTES    
    Name: Test-Port.ps1  
    Author: Boe Prox  
    DateCreated: 18Aug2010   
    List of Ports: http://www.iana.org/assignments/port-numbers  
      
    To Do:  
        Add capability to run background jobs for each host to shorten the time to scan.         
.LINK    
    https://boeprox.wordpress.org 
     
.EXAMPLE    
    Test-Port -computer 'server' -port 80  
    Checks port 80 on server 'server' to see if it is listening  
    
.EXAMPLE    
    'server' | Test-Port -port 80  
    Checks port 80 on server 'server' to see if it is listening 
      
.EXAMPLE    
    Test-Port -computer @("server1","server2") -port 80  
    Checks port 80 on server1 and server2 to see if it is listening  
    
.EXAMPLE
    Test-Port -comp dc1 -port 17 -udp -UDPtimeout 10000
    
    Server   : dc1
    Port     : 17
    TypePort : UDP
    Open     : True
    Notes    : "My spelling is Wobbly.  It's good spelling but it Wobbles, and the letters
            get in the wrong places." A. A. Milne (1882-1958)
    
    Description
    -----------
    Queries port 17 (qotd) on the UDP port and returns whether port is open or not
       
.EXAMPLE    
    @("server1","server2") | Test-Port -port 80  
    Checks port 80 on server1 and server2 to see if it is listening  
      
.EXAMPLE    
    (Get-Content hosts.txt) | Test-Port -port 80  
    Checks port 80 on servers in host file to see if it is listening 
     
.EXAMPLE    
    Test-Port -computer (Get-Content hosts.txt) -port 80  
    Checks port 80 on servers in host file to see if it is listening 
        
.EXAMPLE    
    Test-Port -computer (Get-Content hosts.txt) -port @(1..59)  
    Checks a range of ports from 1-59 on all servers in the hosts.txt file      
            
#>   
[cmdletbinding(  
    DefaultParameterSetName = '',  
    ConfirmImpact = 'low'  
)]  
    Param(  
        [Parameter(  
            Mandatory = $True,  
            Position = 0,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [array]$computer,  
        [Parameter(  
            Position = 1,  
            Mandatory = $True,  
            ParameterSetName = '')]  
            [array]$port,  
        [Parameter(  
            Mandatory = $False,  
            ParameterSetName = '')]  
            [int]$TCPtimeout=1000,  
        [Parameter(  
            Mandatory = $False,  
            ParameterSetName = '')]  
            [int]$UDPtimeout=1000,             
        [Parameter(  
            Mandatory = $False,  
            ParameterSetName = '')]  
            [switch]$TCP,  
        [Parameter(  
            Mandatory = $False,  
            ParameterSetName = '')]  
            [switch]$UDP                                    
        )  
    Begin {  
        If (!$tcp -AND !$udp) {$tcp = $True}  
        #Typically you never do this, but in this case I felt it was for the benefit of the function  
        #as any errors will be noted in the output of the report          
        $ErrorActionPreference = "SilentlyContinue"  
        $report = @()  
    }  
    Process {     
        ForEach ($c in $computer) {  
            ForEach ($p in $port) {  
                If ($tcp) {    
                    #Create temporary holder   
                    $temp = "" | Select Server, Port, TypePort, Open, Notes  
                    #Create object for connecting to port on computer  
                    $tcpobject = new-Object system.Net.Sockets.TcpClient  
                    #Connect to remote machine's port                
                    $connect = $tcpobject.BeginConnect($c,$p,$null,$null)  
                    #Configure a timeout before quitting  
                    $wait = $connect.AsyncWaitHandle.WaitOne($TCPtimeout,$false)  
                    #If timeout  
                    If(!$wait) {  
                        #Close connection  
                        $tcpobject.Close()  
                        Write-Verbose "Connection Timeout"  
                        #Build report  
                        $temp.Server = $c  
                        $temp.Port = $p  
                        $temp.TypePort = "TCP"  
                        $temp.Open = $False 
                        $temp.Notes = "Connection to Port Timed Out"  
                    } Else {  
                        $error.Clear()  
                        $tcpobject.EndConnect($connect) | out-Null  
                        #If error  
                        If($error[0]){  
                            #Begin making error more readable in report  
                            [string]$string = ($error[0].exception).message  
                            $message = (($string.split(":")[1]).replace('"',"")).TrimStart()  
                            $failed = $true  
                        }  
                        #Close connection      
                        $tcpobject.Close()  
                        #If unable to query port to due failure  
                        If($failed){  
                            #Build report  
                            $temp.Server = $c  
                            $temp.Port = $p  
                            $temp.TypePort = "TCP"  
                            $temp.Open = $False 
                            $temp.Notes = "$message"  
                        } Else{  
                            #Build report  
                            $temp.Server = $c  
                            $temp.Port = $p  
                            $temp.TypePort = "TCP"  
                            $temp.Open = $True   
                            $temp.Notes = ""  
                        }  
                    }     
                    #Reset failed value  
                    $failed = $Null      
                    #Merge temp array with report              
                    $report += $temp  
                }      
                If ($udp) {  
                    #Create temporary holder   
                    $temp = "" | Select Server, Port, TypePort, Open, Notes                                     
                    #Create object for connecting to port on computer  
                    $udpobject = new-Object system.Net.Sockets.Udpclient
                    #Set a timeout on receiving message 
                    $udpobject.client.ReceiveTimeout = $UDPTimeout 
                    #Connect to remote machine's port                
                    Write-Verbose "Making UDP connection to remote server" 
                    $udpobject.Connect("$c",$p) 
                    #Sends a message to the host to which you have connected. 
                    Write-Verbose "Sending message to remote host" 
                    $a = new-object system.text.asciiencoding 
                    $byte = $a.GetBytes("$(Get-Date)") 
                    [void]$udpobject.Send($byte,$byte.length) 
                    #IPEndPoint object will allow us to read datagrams sent from any source.  
                    Write-Verbose "Creating remote endpoint" 
                    $remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any,0) 
                    Try { 
                        #Blocks until a message returns on this socket from a remote host. 
                        Write-Verbose "Waiting for message return" 
                        $receivebytes = $udpobject.Receive([ref]$remoteendpoint) 
                        [string]$returndata = $a.GetString($receivebytes)
                        If ($returndata) {
                           Write-Verbose "Connection Successful"  
                            #Build report  
                            $temp.Server = $c  
                            $temp.Port = $p  
                            $temp.TypePort = "UDP"  
                            $temp.Open = $True 
                            $temp.Notes = $returndata   
                            $udpobject.close()   
                        }                       
                    } Catch { 
                        If ($Error[0].ToString() -match "\bRespond after a period of time\b") { 
                            #Close connection  
                            $udpobject.Close()  
                            #Make sure that the host is online and not a false positive that it is open 
                            If (Test-Connection -comp $c -count 1 -quiet) { 
                                Write-Verbose "Connection Open"  
                                #Build report  
                                $temp.Server = $c  
                                $temp.Port = $p  
                                $temp.TypePort = "UDP"  
                                $temp.Open = $True 
                                $temp.Notes = "" 
                            } Else { 
                                <# 
                                It is possible that the host is not online or that the host is online,  
                                but ICMP is blocked by a firewall and this port is actually open. 
                                #> 
                                Write-Verbose "Host maybe unavailable"  
                                #Build report  
                                $temp.Server = $c  
                                $temp.Port = $p  
                                $temp.TypePort = "UDP"  
                                $temp.Open = $False 
                                $temp.Notes = "Unable to verify if port is open or if host is unavailable."                                 
                            }                         
                        } ElseIf ($Error[0].ToString() -match "forcibly closed by the remote host" ) { 
                            #Close connection  
                            $udpobject.Close()  
                            Write-Verbose "Connection Timeout"  
                            #Build report  
                            $temp.Server = $c  
                            $temp.Port = $p  
                            $temp.TypePort = "UDP"  
                            $temp.Open = $False 
                            $temp.Notes = "Connection to Port Timed Out"                         
                        } Else {                      
                            $udpobject.close() 
                        } 
                    }     
                    #Merge temp array with report              
                    $report += $temp  
                }                                  
            }  
        }                  
    }  
    End {  
        #Generate Report  
        $report 
    }
}


function Get-NetworkStatistics {
    <#
    .SYNOPSIS
	    Display current TCP/IP connections for local or remote system

    .FUNCTIONALITY
        Computers

    .DESCRIPTION
	    Display current TCP/IP connections for local or remote system.  Includes the process ID (PID) and process name for each connection.
	    If the port is not yet established, the port number is shown as an asterisk (*).	
	
    .PARAMETER ProcessName
	    Gets connections by the name of the process. The default value is '*'.
	
    .PARAMETER Port
	    The port number of the local computer or remote computer. The default value is '*'.

    .PARAMETER Address
	    Gets connections by the IP address of the connection, local or remote. Wildcard is supported. The default value is '*'.

    .PARAMETER Protocol
	    The name of the protocol (TCP or UDP). The default value is '*' (all)
	
    .PARAMETER State
	    Indicates the state of a TCP connection. The possible states are as follows:
		
	    Closed       - The TCP connection is closed. 
	    Close_Wait   - The local endpoint of the TCP connection is waiting for a connection termination request from the local user. 
	    Closing      - The local endpoint of the TCP connection is waiting for an acknowledgement of the connection termination request sent previously. 
	    Delete_Tcb   - The transmission control buffer (TCB) for the TCP connection is being deleted. 
	    Established  - The TCP handshake is complete. The connection has been established and data can be sent. 
	    Fin_Wait_1   - The local endpoint of the TCP connection is waiting for a connection termination request from the remote endpoint or for an acknowledgement of the connection termination request sent previously. 
	    Fin_Wait_2   - The local endpoint of the TCP connection is waiting for a connection termination request from the remote endpoint. 
	    Last_Ack     - The local endpoint of the TCP connection is waiting for the final acknowledgement of the connection termination request sent previously. 
	    Listen       - The local endpoint of the TCP connection is listening for a connection request from any remote endpoint. 
	    Syn_Received - The local endpoint of the TCP connection has sent and received a connection request and is waiting for an acknowledgment. 
	    Syn_Sent     - The local endpoint of the TCP connection has sent the remote endpoint a segment header with the synchronize (SYN) control bit set and is waiting for a matching connection request. 
	    Time_Wait    - The local endpoint of the TCP connection is waiting for enough time to pass to ensure that the remote endpoint received the acknowledgement of its connection termination request. 
	    Unknown      - The TCP connection state is unknown.
	
	    Values are based on the TcpState Enumeration:
	    http://msdn.microsoft.com/en-us/library/system.net.networkinformation.tcpstate%28VS.85%29.aspx
        
        Cookie Monster - modified these to match netstat output per here:
        http://support.microsoft.com/kb/137984

    .PARAMETER ComputerName
        If defined, run this command on a remote system via WMI.  \\computername\c$\netstat.txt is created on that system and the results returned here

    .PARAMETER ShowHostNames
        If specified, will attempt to resolve local and remote addresses.

    .PARAMETER tempFile
        Temporary file to store results on remote system.  Must be relative to remote system (not a file share).  Default is "C:\netstat.txt"

    .PARAMETER AddressFamily
        Filter by IP Address family: IPv4, IPv6, or the default, * (both).

        If specified, we display any result where both the localaddress and the remoteaddress is in the address family.

    .EXAMPLE
	    Get-NetworkStatistics | Format-Table

    .EXAMPLE
	    Get-NetworkStatistics iexplore -computername k-it-thin-02 -ShowHostNames | Format-Table

    .EXAMPLE
	    Get-NetworkStatistics -ProcessName md* -Protocol tcp

    .EXAMPLE
	    Get-NetworkStatistics -Address 192* -State LISTENING

    .EXAMPLE
	    Get-NetworkStatistics -State LISTENING -Protocol tcp

    .EXAMPLE
        Get-NetworkStatistics -Computername Computer1, Computer2

    .EXAMPLE
        'Computer1', 'Computer2' | Get-NetworkStatistics

    .OUTPUTS
	    System.Management.Automation.PSObject

    .NOTES
	    Author: Shay Levy, code butchered by Cookie Monster
	    Shay's Blog: http://PowerShay.com
        Cookie Monster's Blog: http://ramblingcookiemonster.github.io/

    .LINK
        http://gallery.technet.microsoft.com/scriptcenter/Get-NetworkStatistics-66057d71
    #>	
	[OutputType('System.Management.Automation.PSObject')]
	[CmdletBinding()]
	param(
		
		[Parameter(Position=0)]
		[System.String]$ProcessName='*',
		
		[Parameter(Position=1)]
		[System.String]$Address='*',		
		
		[Parameter(Position=2)]
		$Port='*',

		[Parameter(Position=3,
                   ValueFromPipeline = $True,
                   ValueFromPipelineByPropertyName = $True)]
        [System.String[]]$ComputerName=$env:COMPUTERNAME,

		[ValidateSet('*','tcp','udp')]
		[System.String]$Protocol='*',

		[ValidateSet('*','Closed','Close_Wait','Closing','Delete_Tcb','DeleteTcb','Established','Fin_Wait_1','Fin_Wait_2','Last_Ack','Listening','Syn_Received','Syn_Sent','Time_Wait','Unknown')]
		[System.String]$State='*',

        [switch]$ShowHostnames,
        
        [switch]$ShowProcessNames = $true,	

        [System.String]$TempFile = "C:\netstat.txt",

        [validateset('*','IPv4','IPv6')]
        [string]$AddressFamily = '*'
	)
    
	begin{
        #Define properties
            $properties = 'ComputerName','Protocol','LocalAddress','LocalPort','RemoteAddress','RemotePort','State','ProcessName','PID'

        #store hostnames in array for quick lookup
            $dnsCache = @{}
            
	}
	
	process{

        foreach($Computer in $ComputerName) {

            #Collect processes
            if($ShowProcessNames){
                Try {
                    $processes = Get-Process -ComputerName $Computer -ErrorAction stop | select name, id
                }
                Catch {
                    Write-warning "Could not run Get-Process -computername $Computer.  Verify permissions and connectivity.  Defaulting to no ShowProcessNames"
                    $ShowProcessNames = $false
                }
            }
	    
            #Handle remote systems
                if($Computer -ne $env:COMPUTERNAME){

                    #define command
                        [string]$cmd = "cmd /c c:\windows\system32\netstat.exe -ano >> $tempFile"
            
                    #define remote file path - computername, drive, folder path
                        $remoteTempFile = "\\{0}\{1}`${2}" -f "$Computer", (split-path $tempFile -qualifier).TrimEnd(":"), (Split-Path $tempFile -noqualifier)

                    #delete previous results
                        Try{
                            $null = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c del $tempFile" -ComputerName $Computer -ErrorAction stop
                        }
                        Catch{
                            Write-Warning "Could not invoke create win32_process on $Computer to delete $tempfile"
                        }

                    #run command
                        Try{
                            $processID = (Invoke-WmiMethod -class Win32_process -name Create -ArgumentList $cmd -ComputerName $Computer -ErrorAction stop).processid
                        }
                        Catch{
                            #If we didn't run netstat, break everything off
                            Throw $_
                            Break
                        }

                    #wait for process to complete
                        while (
                            #This while should return true until the process completes
                                $(
                                    try{
                                        get-process -id $processid -computername $Computer -ErrorAction Stop
                                    }
                                    catch{
                                        $FALSE
                                    }
                                )
                        ) {
                            start-sleep -seconds 2 
                        }
            
                    #gather results
                        if(test-path $remoteTempFile){
                    
                            Try {
                                $results = Get-Content $remoteTempFile | Select-String -Pattern '\s+(TCP|UDP)'
                            }
                            Catch {
                                Throw "Could not get content from $remoteTempFile for results"
                                Break
                            }

                            Remove-Item $remoteTempFile -force

                        }
                        else{
                            Throw "'$tempFile' on $Computer converted to '$remoteTempFile'.  This path is not accessible from your system."
                            Break
                        }
                }
                else{
                    #gather results on local PC
                        $results = netstat -ano | Select-String -Pattern '\s+(TCP|UDP)'
                }

            #initialize counter for progress
                $totalCount = $results.count
                $count = 0
    
            #Loop through each line of results    
	            foreach($result in $results) {
            
    	            $item = $result.line.split(' ',[System.StringSplitOptions]::RemoveEmptyEntries)
    
    	            if($item[1] -notmatch '^\[::'){
                    
                        #parse the netstat line for local address and port
    	                    if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'){
    	                        $localAddress = $la.IPAddressToString
    	                        $localPort = $item[1].split('\]:')[-1]
    	                    }
    	                    else {
    	                        $localAddress = $item[1].split(':')[0]
    	                        $localPort = $item[1].split(':')[-1]
    	                    }
                    
                        #parse the netstat line for remote address and port
    	                    if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'){
    	                        $remoteAddress = $ra.IPAddressToString
    	                        $remotePort = $item[2].split('\]:')[-1]
    	                    }
    	                    else {
    	                        $remoteAddress = $item[2].split(':')[0]
    	                        $remotePort = $item[2].split(':')[-1]
    	                    }

                        #Filter IPv4/IPv6 if specified
                            if($AddressFamily -ne "*")
                            {
                                if($AddressFamily -eq 'IPv4' -and $localAddress -match ':' -and $remoteAddress -match ':|\*' )
                                {
                                    #Both are IPv6, or ipv6 and listening, skip
                                    Write-Verbose "Filtered by AddressFamily:`n$result"
                                    continue
                                }
                                elseif($AddressFamily -eq 'IPv6' -and $localAddress -notmatch ':' -and ( $remoteAddress -notmatch ':' -or $remoteAddress -match '*' ) )
                                {
                                    #Both are IPv4, or ipv4 and listening, skip
                                    Write-Verbose "Filtered by AddressFamily:`n$result"
                                    continue
                                }
                            }
    	    		
                        #parse the netstat line for other properties
    	    		        $procId = $item[-1]
    	    		        $proto = $item[0]
    	    		        $status = if($item[0] -eq 'tcp') {$item[3]} else {$null}	

                        #Filter the object
		    		        if($remotePort -notlike $Port -and $localPort -notlike $Port){
                                write-verbose "remote $Remoteport local $localport port $port"
                                Write-Verbose "Filtered by Port:`n$result"
                                continue
		    		        }

		    		        if($remoteAddress -notlike $Address -and $localAddress -notlike $Address){
                                Write-Verbose "Filtered by Address:`n$result"
                                continue
		    		        }
    	    			     
    	    			    if($status -notlike $State){
                                Write-Verbose "Filtered by State:`n$result"
                                continue
		    		        }

    	    			    if($proto -notlike $Protocol){
                                Write-Verbose "Filtered by Protocol:`n$result"
                                continue
		    		        }
                   
                        #Display progress bar prior to getting process name or host name
                            Write-Progress  -Activity "Resolving host and process names"`
                                -Status "Resolving process ID $procId with remote address $remoteAddress and local address $localAddress"`
                                -PercentComplete (( $count / $totalCount ) * 100)
    	    		
                        #If we are running showprocessnames, get the matching name
                            if($ShowProcessNames -or $PSBoundParameters.ContainsKey -eq 'ProcessName'){
                        
                                #handle case where process spun up in the time between running get-process and running netstat
                                if($procName = $processes | Where {$_.id -eq $procId} | select -ExpandProperty name ){ }
                                else {$procName = "Unknown"}

                            }
                            else{$procName = "NA"}

		    		        if($procName -notlike $ProcessName){
                                Write-Verbose "Filtered by ProcessName:`n$result"
                                continue
		    		        }
    	    						
                        #if the showhostnames switch is specified, try to map IP to hostname
                            if($showHostnames){
                                $tmpAddress = $null
                                try{
                                    if($remoteAddress -eq "127.0.0.1" -or $remoteAddress -eq "0.0.0.0"){
                                        $remoteAddress = $Computer
                                    }
                                    elseif($remoteAddress -match "\w"){
                                        
                                        #check with dns cache first
                                            if ($dnsCache.containskey( $remoteAddress)) {
                                                $remoteAddress = $dnsCache[$remoteAddress]
                                                write-verbose "using cached REMOTE '$remoteAddress'"
                                            }
                                            else{
                                                #if address isn't in the cache, resolve it and add it
                                                    $tmpAddress = $remoteAddress
                                                    $remoteAddress = [System.Net.DNS]::GetHostByAddress("$remoteAddress").hostname
                                                    $dnsCache.add($tmpAddress, $remoteAddress)
                                                    write-verbose "using non cached REMOTE '$remoteAddress`t$tmpAddress"
                                            }
                                    }
                                }
                                catch{ }

                                try{

                                    if($localAddress -eq "127.0.0.1" -or $localAddress -eq "0.0.0.0"){
                                        $localAddress = $Computer
                                    }
                                    elseif($localAddress -match "\w"){
                                        #check with dns cache first
                                            if($dnsCache.containskey($localAddress)){
                                                $localAddress = $dnsCache[$localAddress]
                                                write-verbose "using cached LOCAL '$localAddress'"
                                            }
                                            else{
                                                #if address isn't in the cache, resolve it and add it
                                                    $tmpAddress = $localAddress
                                                    $localAddress = [System.Net.DNS]::GetHostByAddress("$localAddress").hostname
                                                    $dnsCache.add($localAddress, $tmpAddress)
                                                    write-verbose "using non cached LOCAL '$localAddress'`t'$tmpAddress'"
                                            }
                                    }
                                }
                                catch{ }
                            }
    
    	    		    #Write the object	
    	    		        New-Object -TypeName PSObject -Property @{
		    		            ComputerName = $Computer
                                PID = $procId
		    		            ProcessName = $procName
		    		            Protocol = $proto
		    		            LocalAddress = $localAddress
		    		            LocalPort = $localPort
		    		            RemoteAddress =$remoteAddress
		    		            RemotePort = $remotePort
		    		            State = $status
		    	            } | Select-Object -Property $properties								

                        #Increment the progress counter
                            $count++
                    }
                }
        }
    }
}


Function Get-Uptime {
    <#
    .SYNOPSIS
    Get-Uptime retrieves boot up information from a Aomputer.
    .DESCRIPTION
    Get-Uptime uses WMI to retrieve the Win32_OperatingSystem
    LastBootuptime property. It displays the start up time
    as well as the uptime.

    Created By: Jason Wasser @wasserja
    Modified: 8/13/2015 01:59:53 PM  
    Version 1.4

    Changelog:
     * Added Credential parameter
     * Changed to property hash table splat method
     * Converted to function to be added to a module.

    .PARAMETER ComputerName
    The Computer name to query. Default: Localhost.
    .EXAMPLE
    Get-Uptime -ComputerName SERVER-R2
    Gets the uptime from SERVER-R2
    .EXAMPLE
    Get-Uptime -ComputerName (Get-Content C:\Temp\Computerlist.txt)
    Gets the uptime from a list of computers in c:\Temp\Computerlist.txt.
    .EXAMPLE
    Get-Uptime -ComputerName SERVER04 -Credential domain\serveradmin
    Gets the uptime from SERVER04 using alternate credentials.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,
                        Position=0,
                        ValueFromPipeline=$true,
                        ValueFromPipelineByPropertyName=$true)]
        [Alias("Name")]
        [string[]]$ComputerName=$env:COMPUTERNAME,
        $Credential = [System.Management.Automation.PSCredential]::Empty
        )

    begin{}

    #Need to verify that the hostname is valid in DNS
    process {
        foreach ($Computer in $ComputerName) {
            try {
                $hostdns = [System.Net.DNS]::GetHostEntry($Computer)
                $OS = Get-WmiObject win32_operatingsystem -ComputerName $Computer -ErrorAction Stop -Credential $Credential
                $BootTime = $OS.ConvertToDateTime($OS.LastBootUpTime)
                $Uptime = $OS.ConvertToDateTime($OS.LocalDateTime) - $boottime
                $propHash = [ordered]@{
                    ComputerName = $Computer
                    BootTime     = $BootTime
                    Uptime       = $Uptime
                    }
                $objComputerUptime = New-Object PSOBject -Property $propHash
                $objComputerUptime
                } 
            catch [Exception] {
                Write-Output "$computer $($_.Exception.Message)"
                #return
                }
        }
    }
    end{}
}


Function CreateADPC {
    <#
    .SYNOPSIS
        Создает объект типа компьютер в контейнере домена
    .DESCRIPTION
        Данная функция создает объект типа компьютер в контейнере домена
    .EXAMPLE
        CreateADPC -ComputerName "Win-10" -OUPath "OU=Computers,DC=google,DC=com"
        Создаст в указанном контейнере объект компьютер с именем "Win-10"
    .EXAMPLE
        CreateADPC -ComputerName "Win-10"
        Создаст в контейнере "OU=Computers,OU=ЕвроХим УКК,OU=Регион,OU=Accounts,DC=usl,DC=eurochem,DC=ru" объект компьютер с именем "Win-10"
    .EXAMPLE
        CreateADPC -ComputerName "Win-10 Win-7 Win-8 Win-XP"
        Создаст в контейнере "OU=Computers,OU=ЕвроХим УКК,OU=Регион,OU=Accounts,DC=usl,DC=eurochem,DC=ru" объект компьютеров с именами "Win-10" "Win-7" "Win-8" "Win-XP"
    .PARAMETER ComputerName
        Имя компьютера (обязательный параметр, только латинские символы и цифры)
    .PARAMETER OUPath
        Контейнер, в котором необходимо создать объект компьютера, если контейнер не указан, то по-умолчанию значение контейнера равно "OU=Computers,OU=ЕвроХим УКК,OU=Регион,OU=Accounts,DC=usl,DC=eurochem,DC=ru" (необязательный параметр)
    #>
    param (
        [PARAMETER(Mandatory=$True,Position=0)][String]$ComputerName,
        [PARAMETER(Mandatory=$False,Position=1)][String]$OUPath="OU=Computers,OU=ЕвроХим УКК,OU=Регион,OU=Accounts,DC=usl,DC=eurochem,DC=ru"
        <#УРСС $OUPath="OU=Computers,OU=Специалисты АХО,OU=Административная служба,OU=ООО Урал-ремстройсервис,OU=Дочерние предприятия,OU=Регион,OU=Accounts,DC=usl,DC=eurochem,DC=ru"#>
    )

    $Computer = $ComputerName.Split()
    
    $Computer | foreach {

        if($_ -match "[а-я]"){

            Write-Host "Имя компьютера может содержать только символы латинского алфавита, цифры, специальные знаки ( - , _ )" -ForegroundColor Red
            return

        }

        if($_ -notlike "Mac-*"){

            $_ = $_.ToLower()
            $_ = "Mac-$_"

        } else {

            $_ = ($_.Substring(4)).ToLower()
            $_ = "Mac-$_"

        }

        if($_.Length -gt 15){

            Write-Host "Длина имени компьютера не должна превышать 15 символов" -ForegroundColor Red
            return

        }

        if($_.Length -lt 15){

            Write-Host "Длина имени компьютера меньше 15 символов, проверьте корректность написания имени компьютера" -ForegroundColor Red
            return

        }

        $NewPC = New-ADComputer -Name $_ -Path $OUPath -PassThru -Confirm

        if($NewPC){

            $NewPC
            Write-Host "В контейнере  $OUPath  успешно создан компьютер с именем $_" -ForegroundColor Green
            
        } else {
        
            Write-Host "Операция отменена пользователем" -ForegroundColor Red

        }

    }
}


Function Set-SMS_SCCM {

    <#
    #>
    param (
        [PARAMETER(Mandatory=$False,Position=0)][String]$ComputerName='localhost'
    )
    if($ComputerName -notmatch 'localhost'){
        invoke-command -ScriptBlock {
            $sms = new-object –comobject “Microsoft.SMS.Client” 
            $AssignedSite = $sms.GetAssignedSite()
            if($AssignedSite -eq "USL"){
                Write-Host "Уже установлен сайт - $AssignedSite" -ForegroundColor Green
            } else {
                $sms.SetAssignedSite('USL')
                $usl = $sms.GetAssignedSite()
                Write-Host "Текущий сайт $AssignedSite заменен на - $usl" -ForegroundColor DarkYellow
            }
        } -ComputerName  $ComputerName
    } else {
        $sms = new-object –comobject “Microsoft.SMS.Client”
        $AssignedSite = $sms.GetAssignedSite()
        if($AssignedSite -eq "USL"){
            Write-Host "Уже установлен сайт - $AssignedSite" -ForegroundColor Green
        } else {
            $sms.SetAssignedSite('USL')
            $usl = $sms.GetAssignedSite()
            Write-Host "Текущий сайт $AssignedSite заменен на - $usl" -ForegroundColor DarkYellow
        }
    }
}


Function RControl {

    <#
    .SYNOPSIS
        Удаленное подключение к компьютеру по имени компьютера или имени пользователя
    .DESCRIPTION
        Данная функция выполняет поиск в сети компьютера пользователя по имени компьютера или по имени пользователя, и используя приложение "Configuration Manager Remote Control", осуществляет соединение с ним.
    .EXAMPLE
        RControl "Иванов Иван Иванович"
        Найдет в сети компьютер, на котором в данный момент залогинен пользователь "Иванов Иван Иванович" и выполнит удаленное подключение к компьютеру.
    .PARAMETER UserName
        Имя пользователя, для исключения обнаружения нескольких ПК, желательно указывать полное ФИО. В функцию встроена проверка на количество найденных ПК, поэтому если их количество будет более одного, то будет выведено соответствующее предупреждение.
    .PARAMETER Computer
        Имя компьютера.


    #>
    param (
        [PARAMETER(Mandatory=$False,Position=0)][String]$UserName,
        [PARAMETER(Mandatory=$False,Position=1)][String]$Computer
    )

    Function GetComputerInfo {

        <#
        #>
        param (
            [PARAMETER(Mandatory=$True,Position=0)][String]$ComputerName
        )

        $ComputerInfo = @()

        $Comp = Get-ADComputer -Filter "Name -like '$ComputerName'" -Properties Description, IPV4address
        $IPV4address = $Comp.IPV4address
        $UserFullName = $Comp.Description
        $User = Get-ADUser -Filter "CN -like '*$UserFullName*'" -Properties Title, Description, ipphone
        $Title = $User.title
        $ipphone = $User.ipphone
        $Department = $User.Description

        $ComputerInfo += New-Object PsObject -Property @{

            Name = $ComputerName
            IPV4address = $IPV4address
            UserFullName = $UserFullName
            Title = $Title
            ipphone = $ipphone
            Department = $Department

        }

        return $ComputerInfo
    }


    if($UserName -and !$Computer){

        $UserComputer = Get-ADComputer -Filter "Description -like '*$UserName*'" -Properties Description

        if($UserComputer){

            $OnlineComputerNames = @()
            $OfflineComputerNames = @()

            $UserComputer | foreach {
        
                $ComputerName = $_.Name
                $User = $_.Description

                if(Test-Connection $ComputerName -Count 2 -Quiet){

                    $OnlineComputerNames += $ComputerName

                } else {

                    $OfflineComputerNames += $ComputerName
            
                }
            }

            $count = $OnlineComputerNames.count

            if($count -gt 1){
                    Write-Host ""
                    Write-Host "В сети найдено $count компьютера(ов) с пользователем по имени $UserName." -ForegroundColor DarkYellow
                    Write-Host ""
                    Write-Host "Computers online:"
                    Write-Host "----------------------------"

                    $OnlineComputerNames | foreach {

                        $info = GetComputerInfo($_)    
                        Write-Host ($info.name).ToUpper() "`t" $info.IPV4address "`t" $info.UserFullName "`t" $info.Title "`t" $info.Department "`t" $info.ipphone -ForegroundColor Green
                    
                    }
                    Write-Host ""
                    Write-Host "Computers offline:"
                    Write-Host "----------------------------"

                    $OfflineComputerNames | foreach {

                        $info = GetComputerInfo($_)
                        Write-Host ($info.name).ToUpper() "`t" $info.IPV4address "`t" $info.UserFullName "`t" $info.Title "`t" $info.Department "`t" $info.ipphone -ForegroundColor Red

                    }

                    Write-Host ""
                    $ComputerName = Read-Host -Prompt "Введите имя одного из найденных компьютеров "
                    $info = GetComputerInfo($ComputerName)
                    Start-Process -FilePath CmRcViewer.exe -WorkingDirectory "c:\Programs\RemoteControl" -ArgumentList "$ComputerName \\usl131.usl.eurochem.ru"
                    Write-Host ($info.name).ToUpper() "`t" $info.IPV4address "`t" $info.UserFullName "`t" $info.Title "`t" $info.Department "`t" $info.ipphone -ForegroundColor Green
                    return

                }

        } else {

            Write-Host "Не найден компьютер с пользователем по имени $UserName" -ForegroundColor Red
            return

        }

        $ComputerName = $OnlineComputerNames[0]
        $info = GetComputerInfo($ComputerName)
        Write-Host ($info.name).ToUpper() "`t" $info.IPV4address "`t" $info.UserFullName "`t" $info.Title "`t" $info.Department "`t" $info.ipphone -ForegroundColor Green

        Start-Process -FilePath CmRcViewer.exe -WorkingDirectory "c:\Programs\RemoteControl" -ArgumentList "$ComputerName \\usl131.usl.eurochem.ru"
        return

    } elseif ( $Computer -and !$UserName ){

        if($Computer -like "10.80.*"){
        
            if(Test-Connection $Computer -Count 2 -Quiet){
    
                Start-Process -FilePath CmRcViewer.exe -WorkingDirectory "c:\Programs\RemoteControl" -ArgumentList "$Computer \\usl131.usl.eurochem.ru"
                Write-Host $Computer -ForegroundColor Green
                return

            } else {
            
            Write-Host "Компьютера с ip-адресом $Computer нет в сети" -ForegroundColor Red
                return
            }
        }

        $UserComputer = Get-ADComputer -Filter "Name -like '*$Computer*'"

        if($UserComputer){

            if(Test-Connection $Computer -Count 2 -Quiet){
    
                Start-Process -FilePath CmRcViewer.exe -WorkingDirectory "c:\Programs\RemoteControl" -ArgumentList "$Computer \\usl131.usl.eurochem.ru"
                Write-Host $Computer -ForegroundColor Green
                return

            } else {
            
            Write-Host "Компьютера с именем $Computer нет в сети" -ForegroundColor Red
            
            }

        } else {
        
        Write-Host "Не найден компьютер с именем $Computer, проверьте корректность написания имени" -ForegroundColor Red
        return
        }

    } else {
    
        Write-Host "Необходимо указать что-то одно: или Имя Компьютера или Имя Пользователя" -ForegroundColor DarkYellow
        return
    }
}


Function GetComputerInfo {

    <#
    #>
    param (
        [PARAMETER(Mandatory=$True,Position=0)][String]$ComputerName
    )

    $ComputerInfo = @()

    $Comp = Get-ADComputer -Filter "Name -like '$ComputerName'" -Properties Description, IPV4address
    $IPV4address = $Comp.IPV4address
    $UserFullName = $Comp.Description
    $User = Get-ADUser -Filter "CN -like '*$UserFullName*'" -Properties Title, Description, ipphone
    $Title = $User.title
    $ipphone = $User.ipphone
    $Department = $User.Description

    $ComputerInfo += New-Object PsObject -Property @{

        Name = $ComputerName
        IPV4address = $IPV4address
        UserFullName = $UserFullName
        Title = $Title
        ipphone = $ipphone
        Department = $Department

    }

    return $ComputerInfo
}


Function ChangeIPAddress {

    <#
    #>
    param (
        [PARAMETER(Mandatory=$True,Position=0)][String]$IPAddress
    )

    $NetAdapter = Get-NetAdapter -Name Ethernet

    if($NetAdapter){

        $NetAdapter | Set-NetIPInterface -Dhcp Enabled
        $NetAdapter | Set-DnsClientServerAddress -ResetServerAddresses
        Start-Sleep -Seconds 10

        if(Test-Connection 10.80.128.10 -Count 4 -Quiet){

            Write-Host "Компьютер успешно получил ip-адрес по DHCP" -ForegroundColor Green
            return

        } else {
        
            $NetAdapter | New-NetIPAddress -IPAddress $IPAddress -PrefixLength 24 -DefaultGateway 10.80.244.1 -ErrorAction SilentlyContinue
            $NetAdapter | Set-DnsClientServerAddress -ServerAddresses "10.80.128.10 10.80.128.11"
            Write-Host "Компьютер не получил ip-адрес по DHCP, установлен статический ip-адрес $IPAddress" -ForegroundColor Red
            Start-Sleep -Seconds 3
            Test-Connection 10.80.128.10 -Count 4
        
        }

    } else {
    
        Write-Host "Сетевой адаптер с именем Ethernet не найден" -ForegroundColor Red
    }

}



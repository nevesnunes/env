# Running

net stop com.docker.service
taskkill /IM "dockerd.exe" /F
taskkill /IM "Docker for Windows.exe" /F
net start com.docker.service
& "c:\program files\docker\docker\Docker for Windows.exe"

cd ~/opt/graylog
docker-compose up

# Windows

docker exec --user root -it graylog_graylog_1 /bin/bash
sed -i 's/\(message_journal_enabled\).*/\1 = false/g' data/config/graylog.conf
||
http://docs.graylog.org/en/3.0/pages/installation/virtual_machine_appliances.html#virtual-machine-appliances

# Testing

apt upgrade
apt install net-tools netcat vim

netstat -tulpn | grep 12201
=> UDP

curl -v -X POST http://localhost:12201/gelf -d '{"short_message":"Hello there", "host":"example.org", "facility":"test", "_foo":"bar"}'
=>
TCP    127.0.0.1:12201        127.0.0.1:45856        TIME_WAIT       0

echo -n -e '{ "version": "1.1", "host": "example.org", "short_message": "A short message", "level": 5, "_some_info": "foo" }'"\0" >/dev/udp/127.0.0.1/12201
||
echo -n -e '{ "version": "1.1", "host": "example.org", "short_message": "A short message", "level": 5, "_some_info": "foo" }'"\0" | nc -vv -u -w1 127.0.0.1 12201
=> OK
|| ps1
!! powershell mangles null bytes
=>
https://stackoverflow.com/questions/31855705/write-bytes-to-a-file-natively-in-powershell
powercat -c 127.0.0.1 -p 12201 -u -t 1 -i C:\Users\foo\1

echo 'First log message' | nc 127.0.0.1 5555
|| ps1
echo 'First log message' | powercat -c 127.0.0.1 -p 5555
=> OK

# Clear logs

echo "" > $(docker inspect --format='{{.LogPath}}' container_name)
|| ps1
https://blog.jongallant.com/2017/11/ssh-into-docker-vm-windows/
    "C:\Users\Public\Documents\Hyper-V\Virtual hard disks\MobyLinuxVM.vhdx"

# Integration

https://docs.graylog.org/en/3.0/pages/gelf.html
    https://github.com/mp911de/logstash-gelf/

https://docs.graylog.org/en/3.0/pages/sidecar.html
    https://gryzli.info/2019/02/15/installing-and-configuring-filebeat-on-centos-rhel/#3OptionalParsing_Application_Specific_Logs_By_Using_Filebeat_Modules

manual
    https://github.com/severb/graypy
    https://stackoverflow.com/questions/19561089/tail-f-over-ssh-with-paramiko-has-an-increasing-delay/19562345#19562345
    https://stackoverflow.com/questions/30627810/how-to-parse-this-custom-log-file-in-python
    bash - tail over ssh, redirect to separate file descriptor, xargs echo to GELF port
        :) client-side aggregation

# +

http://www.andrew-programming.com/2018/09/13/setup-graylog-on-local-machine-and-sent-logs-to-it-from-java-application/
    System > Inputs > GELF UDP
        https://docs.graylog.org/en/3.0/pages/sending_data.html#gelf-sending-from-applications

docker-compose
    https://docs.graylog.org/en/3.0/pages/installation/docker.html?highlight=compose#persisting-data
    https://gist.github.com/jonlabelle/bd667a97666ecda7bbc4f1cc9446d43a

docker-compose logs --follow
docker-compose logs --no-color --tail=1000 CONTAINER_NAME | vim -



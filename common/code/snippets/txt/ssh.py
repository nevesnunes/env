import paramiko
import datetime
import subprocess # run it locally if you want, use this for Bash commands

def run_netflow_cmd(command):
    
    rwflow_server_ip = "1.2.3.4" # SiLK box
    user_name="netflow"
    keyfile="/home/marius/.ssh/id_rsa"
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(rwflow_server_ip, username=user_name, key_filename=keyfile)
    stdin, stdout, stderr = ssh.exec_command(command + "&& echo 'done'")

    for line in stderr.readlines():
        print line

    for line in stdout.readlines():
        # print line
        exit_status = stdout.channel.recv_exit_status()  # Blocking call
    
    if exit_status == 0:
        print str(datetime.datetime.today()) + ": Command finished successfully."
    else:
        print("Error", exit_status)
    ssh.close()

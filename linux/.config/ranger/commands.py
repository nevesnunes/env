from ranger.api.commands import *
from subprocess import PIPE
class fcd(Command):
    def execute(self):
        args = self.rest(1)
        command="bash -c 'source ~/.bashrc ;"
        command+="locate -e \"$(pwd)\" | fzf"
        command+="'"
        fzf = self.fm.execute_command(command, stdout=PIPE)
        stdout, stderr = fzf.communicate()
        directory = stdout.decode('utf-8').rstrip('\n')
        self.fm.cd(directory)

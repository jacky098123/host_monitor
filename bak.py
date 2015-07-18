#/usr/bin/python
# -*- coding: utf8 -*-

__author__  = 'Jeff Yang <Jeff.007.yang@gmail.com>'
__date__    = '2012-01-07'

import os
import sys
import re
import subprocess
import kxlog
import pdb
import httplib
import urllib

hosts = [
'60.28.209.23       yangrq,jiemw',
'60.28.209.24       yangrq,jiemw',
'60.28.205.249      yangrq',
'60.28.214.106      yangrq',
'60.28.209.10       yangrq,zhangchi',
'60.28.214.105      yangrq,zhangchi',
'60.28.214.107      yangrq,zhangchi',
'60.28.205.246      yangrq,zhangchi',
]

LOCAL_IP_ADDR = subprocess.Popen("/sbin/ifconfig eth0 |grep -w inet|awk '{print $2}' |awk -F: '{print $2}'",
                                 shell=True, stdout=subprocess.PIPE).communicate()[0].strip()
LOCAL_ID    = LOCAL_IP_ADDR.split('.')


class ProcessExclude():
    def __init__(self, user, pattern, mem_kill, mem_stop, mem_sms, mem_mail, desc='', change_user=0):
        self.user       = user
        self.pattern    = pattern
        self.mem_kill   = mem_kill
        self.mem_stop   = mem_stop
        self.mem_sms    = mem_sms
        self.mem_mail   = mem_mail
        self.desc       = desc
        self.change_user= 0

    def Dump(self):
        print '\t\t', self.user, self.pattern, self.mem_kill, self.mem_stop, self.mem_sms, self.mem_mail, self.desc, self.change_user

class Host():
    def __init__(self, ip, admin, local_ip=None):
        self._ip    = ip
        self._local_ip      = ip
        if local_ip:
            self._local_ip  = local_ip
        self._admin = admin
        self._logger    = kxlog.KXLog.Instance()
        self._mem_kill  = 65
        self._mem_stop  = 65
        self._mem_sms   = 50
        self._mem_mail  = 45
        self._exclude = []
#        self._exclude.append(ProcessExclude('*','mysql',70,70,60,45))
#        self._exclude.append(ProcessExclude('*', 'mongod',70,70,60,45))

        cmd = "cat /etc/passwd|awk -F: '{if ($3>999) print $1}'"
        self._passwd_user = subprocess.Popen(cmd, shell=True,
                                             stdout=subprocess.PIPE).communicate()[0].strip().split('\n')
        self._home_user = subprocess.Popen('ls /home', shell=True,
                                           stdout=subprocess.PIPE).communicate()[0].strip().split('\n')

    def GetIp(self):
        return self._ip

    def GetID(self):
        l   = self._ip.split('.')
        return l[len(l)-1] + ":"

    def GetAdmin(self):
        return self._admin


    def Dump(self):
        print '\tadmin:\t', self._admin
        print '\tip_addr:\t', self._ip
        print '\tlocal_ip:\t', self._local_ip
        print '\tmemory_exclude:'
        for exclude in self._exclude:
            exclude.Dump()


    def AddProcessExclude(self, exclude):
        self._exclude.append(exclude)


    def DoAlert(self, to, ip, level, title, content=''):
        if not content:
            content = title

        conn = httplib.HTTPConnection("60.28.209.56", 8092)
        conn.set_debuglevel(5)
        try:
            params = urllib.urlencode({'to':to, 'content':content, 'title': self.GetID() + title, 'level':level})
            params = params.replace(" ", "_")
            headers = {"Content-type": "application/x-www-form-urlencoded","Accept": "text/plain"}
            conn.request('POST', '/alert', params, headers)
            resp = conn.getresponse()
            if resp.status == 200:
                print resp.read()
            else:
                print "ERROR: request error: ", resp.reason
        except:
            print traceback.print_exc()


    def DoQuota(self):
        self._logger.info("DoQuota")
        for user in self._home_user:
            if user not in self._passwd_user:
                continue

            cmd = "/usr/bin/quota -u %s |grep \"/dev\"" % user
            quota_str = subprocess.Popen(cmd, shell=True,
                                         stdout=subprocess.PIPE).communicate()[0].strip()

            msg =  "quota: %s get limitation" % user
            items = quota_str.split()
            if len(items) > 7:
                self.DoAlert('%s,%s'%(user,self._admin), self._ip, 'mail', msg, 'quota str: %s'%quota_str)


    def DoDisk(self):
        self._logger.info("DoDisk")
        cmd = "df -l | grep ^/ | awk '{print $1, $6, $5}'"
        dev_str = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).communicate()[0]
        dev_items = dev_str.strip().split('\n')

        msg_list= []
        warn_level = 'mail'
        for item in dev_items:
            item = item.strip('%').split()
            if float(item[2]) <= 92:
                continue

            if float(item[2]) > 95:
                warn_level = 'sms'
            msg_list.append('dev: %s usage: %s ' % (item[0], item[2]))

        if len(msg_list) > 0:
            msg = 'Warn:' + ', '.join(msg_list)
            self.DoAlert(self._admin, self._ip, warn_level, msg, 'original string: ' + dev_str)

    def DoPing(self, remote_ip, remote_admin):
        self._logger.info("DoPing")
        if self._ip == remote_ip:
            return True

        cmd = '/bin/ping -c 3 %s | grep -w ttl | wc -l ' % remote_ip
        ping_count = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).communicate()[0].strip()

        msg = 'Host_%s_unreachable' % remote_ip
        if int(ping_count) == 0:
            self.DoAlert(remote_admin, remote_ip, 'sms', msg)
        elif int(ping_count) < 3:
            self.DoAlert(remote_admin, remote_ip, 'mail', msg)
        else:
            pass # normal


    def DoMemory(self):
        self._logger.info("DoMemory")
        total   = subprocess.Popen("free -m |grep Mem |awk '{print $2}'",
                                   shell=True, stdout=subprocess.PIPE).communicate()[0]
        free    = subprocess.Popen("free -m |grep \"buffers/cache\"|awk '{print $4}'",
                                   shell=True, stdout=subprocess.PIPE).communicate()[0]
        total   = float(total.strip())
        free    = float(free.strip())
        
        if free/total < 0.2 or free < 500:
            msg = 'Warn: low mem: %d, total: %d' % (free, total)
            self.DoAlert(self._admin, self._ip, 'sms', msg)


    def DoProcess(self):
        self._logger.info("DoProcess")
        cmd = "ps ax -o pid,user,%mem,comm,args|awk '{if ($3>40) print $0}'"
        process_list = subprocess.Popen(cmd, shell=True,
                                        stdout=subprocess.PIPE).communicate()[0].split("\n")
        for process_info in process_list:
            item = process_info.strip().split()
            if len(item) < 4:
                continue

            exclude_flag = False
            for exclude in self._exclude:
                if exclude.change_user:
                    item[1] = ChangeUser(item[1])
                if re.search(exclude.pattern, item[4]) == None:
                    continue
                if not (exclude.user == '*' or exclude.user == item[1]):
                    continue
                self.ProcessAlert(process_info, exclude.mem_kill, exclude.mem_stop, exclude.mem_sms, exclude.mem_mail, True)
                exclude_flag = True

            if not exclude_flag:
                self.ProcessAlert(process_info, self._mem_kill, self._mem_stop, self._mem_sms, self._mem_mail, False)


    def ProcessAlert(self, process_info, mem_kill, mem_stop, mem_sms, mem_mail, skip_flag):
        self._logger.info("%s" % process_info)
        item = process_info.strip().split()
        info = "process: %s, use mem: %s" % (item[3], item[2])
        alert_to = self._admin + ',' + item[1]
        alert_content = "info: %s" % process_info

        if item[2] > mem_kill:
            subprocess.call("kill -2 %s && sleep 5" % item[0], shell=True)
            subprocess.call("kill -9 %s && sleep 5" % item[0], shell=True)
            exist = subprocess.Popen("ps --no-heading -p %s" % item[0], shell=True).communicate()[0]
            if skip_flag:
                msg = "Kill(s)"
            else:
                msg = "Kill"
            if exist and len(exist.strip()) > 0:
                msg = msg + " %s failed" % info
            else:
                msg = msg + " %s succeed" % info
            self.DoAlert(alert_to, self._ip, 'sms', msg, alert_content)
        elif item[2] > mem_stop:
            subprocess.call("kill -STOP %s" % item[0], shell=True)
            if skip_flag:
                msg = "Kill(s) stop: %s" % info
            else:
                msg = "Kill stop: %s" % info
            self.DoAlert(alert_to, self._ip, 'sms', msg, alert_content)
        elif item[2] > mem_sms:
            if skip_flag:
                msg = "Warn(s): %s" % info
            else:
                msg = "Warn: %s" % info
            self.DoAlert(alert_to, self._ip, 'sms', msg, alert_content)
        else:
            if skip_flag:
                msg = "Info(s): %s" % info
            else:
                msg = "Info: %s" % info
            self.DoAlert(alert_to, self._ip, 'mail', msg, alert_content)


    def ChangeUser(self, uid):
        user = subprocess.Popen('id -u %s' % uid, shell=True,
                                stdout=subprocess.PIPE).communicate()[0].strip()
        return user


def build_host():
    host_dict = {}
    for host in hosts:
        items = host.split()
        if len(items) != 2:
            print 'invalid host', host
            continue
        host_dict[items[0]]   = Host(items[0], items[1])

    path = os.path.dirname(os.path.realpath(__file__))
    exclude_file = path + '/memory_exclude.txt'
    is_head = True
    file_obj = open(exclude_file)
    try:
        for line in file_obj:
            if is_head:
                is_head = False
                continue

            items = line.split()
            if host_dict.has_key(items[0]):
                host_dict[items[0]].AddProcessExclude(ProcessExclude(items[1],items[2],items[3],items[4],items[5],items[6]))
            elif items[0] == '*':
                for host in host_dict.itervalues():
                    host.AddProcessExclude(ProcessExclude(items[1],items[2],items[3],items[4],items[5],items[6]))
            else:
                print 'invalid memory', line
    finally:
        file_obj.close()

    return host_dict


def ping_monitor(host_dict):
    local_host = None
    for remote_ip, host in host_dict.iteritems():
        if remote_ip == LOCAL_IP_ADDR:
            local_host = host
            break

    if not local_host:
        return

    for remote_ip, host in host_dict.iteritems():
        if remote_ip == LOCAL_IP_ADDR:
            continue

        local_host.DoPing(host.GetIp(), host.GetAdmin())


def test():
    host_dict = build_host()
    host_dict = build_host()
    if not host_dict.has_key(LOCAL_IP_ADDR):
        logger.warn("local ip is unregisterd")
        sys.exit(0)
    host = host_dict[LOCAL_IP_ADDR]
    host.Dump()


if __name__ == '__main__':
#    test()
#    sys.exit()

    logger = kxlog.KXLog.Instance()
    logger.info(" ------------ main ------------ ")

    host_dict = build_host()
    if not host_dict.has_key(LOCAL_IP_ADDR):
        logger.warn("local ip is unregisterd")
        sys.exit(0)
    host = host_dict[LOCAL_IP_ADDR]

    if len(sys.argv) != 2:
        print "python %s type" % __file__
        sys.exit(0)

    if sys.argv[1] == "disk_monitor":
        host.DoDisk()
    elif sys.argv[1] == "quota_monitor":
        host.DoQuota()
    elif sys.argv[1] == "ping_monitor":
        ping_monitor(host_dict)
    elif sys.argv[1] == "process_monitor":
        host.DoProcess()
    elif sys.argv[1] == "memory_monitor":
        host.DoMemory()
    else:
        print "invalid argument"

    kxlog.KXLog.Finish()

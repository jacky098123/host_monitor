
import os
import sys
import re
import logging
import traceback
import subprocess

FILE_PATH   = os.path.dirname(os.path.realpath(__file__))
if FILE_PATH not in sys.path:
    os.path.append(FILE_PATH)

import config


logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s %(levelname)s %(message)s',
                   filename='%s/run.log' % FILE_PATH,
                   filemode='a')

LOCAL_IP_ADDR   = subprocess.Popen("/sbin/ifconfig eth1 |grep -w inet|awk '{print $2}' |awk -F: '{print $2}'",
                                   shell=True, stdout=subprocess.PIPE).communicate()[0].strip()
ETH0_ADDR       = subprocess.Popen("/sbin/ifconfig eth0 |grep -w inet|awk '{print $2}' |awk -F: '{print $2}'",
                                   shell=True, stdout=subprocess.PIPE).communicate()[0].strip()
PASSWORD_USER   = subprocess.Popen("cat /etc/passwd|awk -F: '{if ($3>999) print $1}'", shell=True,
                                   stdout=subprocess.PIPE).communicate()[0].strip().split('\n')
HOME_USER       = subprocess.Popen('ls /home', shell=True,
                                   stdout=subprocess.PIPE).communicate()[0].strip().split('\n')

class ProcessExclude():
    def __init__(self, **kwargs):
        self.user     = kwargs['user']
        self.process  = kwargs['process']
        self.mem_kill = kwargs['mem_kill']
        self.mem_sms  = kwargs['mem_sms']
        self.mem_mail = kwargs['mem_mail']

    def Match(self, process_info):
        pass

    def __str__(self):
        return "\tProcessExclude: %s %s %d %d %d" % (self.user, self.process, self.mem_kill, self.mem_sms, self.mem_mail)


class Host():
    def __init__(self, host_conf):
        dest_dict = {}
        for k,v in config.default_host_config.iteritems():
            dest_dict[k] = v
        for k,v in host_conf.iteritems():
            dest_dict[k] = v

        self._eth0             = ETH0_ADDR
        self._host             = LOCAL_IP_ADDR # also dest_dict['host']
        self._admin            = ','.join(dest_dict['admin'].split())
        self._mail_notify_all  = dest_dict['mail_notify_all']
        self._sms_notify_all   = dest_dict['sms_notify_all']
        self._notify_skip_user = ','.join(dest_dict['notify_skip_user'].split())
        self._disk_mail        = dest_dict['disk_mail']
        self._disk_sms         = dest_dict['disk_sms']
        self._mem_mail         = dest_dict['mem_mail']
        self._mem_sms          = dest_dict['mem_sms']

        # get process exclude
        self._process_exclude = []
        for conf in dest_dict['process_exclude']:
            self._process_exclude.append( ProcessExclude(**conf))

        # get default process setting
        self._process_conf  = {}
        default_process_setting = {}
        concrete_process_setting= {}
        for conf in config.default_process_config:
            if conf['host'] == '*' and conf['user'] == '*' and conf['process'] == '*':
                default_process_setting = conf
            if conf['host'] == LOCAL_IP_ADDR and conf['user'] == '*' and conf['process'] == '*':
                concrete_process_setting = conf
        dest_dict = {}
        for k,v in default_process_setting.iteritems():
            dest_dict[k] = v
        for k,v in concrete_process_setting.iteritems():
            dest_dict[k] = v
        self._process_conf['mem_kill'] = dest_dict['mem_kill']
        self._process_conf['mem_sms']  = dest_dict['mem_sms']
        self._process_conf['mem_mail'] = dest_dict['mem_mail']


    def Dump(self):
        print '\teth0: \t\t%s '       % self._eth0
        print '\thost: \t\t%s'        % self._host
        print '\tadmin: \t\t%s'       % self._admin
        print '\tmail_notify_all: \t%s'     % self._mail_notify_all
        print '\tsms_notify_all: \t%s'      % self._sms_notify_all
        print '\tnotify_skip_user: \t%s'    % str(self._notify_skip_user)
        print '\tdisk_mail: \t%s'   % self._disk_mail
        print '\tdisk_sms: \t%s'    % self._disk_sms
        print '\tmem_mail: \t%s'    % self._mem_mail
        print '\tmem_sms: \t%s'     % self._mem_sms
        print '\tdefault process config: %s' % str(self._process_conf)
        for exclude in self._process_exclude:
            print exclude

    def HandleService(self, action, to, level, title, content):
        import httplib
        import urllib
        conn = httplib.HTTPConnection("60.28.209.56", 8092)
        conn.set_debuglevel(5)
        try:
            params = urllib.urlencode({'to':to, 'content':content, 'title':title, 'level':level})
            params = params.replace(" ", "_")
            headers = {"Content-type": "application/x-www-form-urlencoded","Accept": "text/plain"}
            conn.request('POST', '/%s' % action, params, headers)
            resp = conn.getresponse()
            if resp.status == 200:
                print resp.read()
            else:
                print "ERROR: request error: ", resp.reason
        except:
            print traceback.print_exc()

    # you need know the web service protocol
    def HandleNotification(self, to, ip, level, title, content=''):
        if not content:
            content = title

        new_title = ip.split('.')[3] + title
        all_user = ','.join(set(HOME_USER) & set(PASSWORD_USER))

        if self._mail_notify_all:
            if level == 'sms':
                self.HandleService('sms', to, 'sms', new_title, new_title)
            self.HandleService('mail', all_user, 'mail', new_title, content)
        else:
            self.HandleService('alert', to, level, new_title, content)

    def DoQuota(self):
        logging.debug("DoQuota is called")
        for user in HOME_USER:
            if user not in PASSWORD_USER:
                continue

            cmd = "/usr/bin/quota -u %s |grep \"/dev\"" % user
            quota_str = subprocess.Popen(cmd, shell=True,
                                         stdout=subprocess.PIPE).communicate()[0].strip()

            msg =  "quota: %s get limitation" % user
            items = quota_str.split()
            if len(items) > 7:
                self.HandleNotification('%s,%s'%(user,self._admin), self._host, 'mail', msg, 'quota str: %s'%quota_str)

    def DoDisk(self):
        logging.debug("DoDisk is called")
        cmd = "df -l | grep ^/ | awk '{print $1, $6, $5}'"
        dev_str = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).communicate()[0]
        dev_items = dev_str.strip().split('\n')

        msg_list= []
        warn_level = 'mail'
        for item in dev_items:
            item = item.strip('%').split()
            if float(item[2]) <= self._disk_mail:
                continue

            if float(item[2]) > self._disk_sms:
                warn_level = 'sms'
            msg_list.append('dev: %s usage: %s' % (item[0], item[2]))

        if len(msg_list) > 0:
            msg = 'Warn:' + ', '.join(msg_list)
            self.HandleNotification(self._admin, self._host, warn_level, msg, 'original string: ' + dev_str)

    def DoPing(self, remote_ip, remote_admin):
        logging.debug("DoPing is called")
        if self._host == remote_ip:
            return True

        cmd = '/bin/ping -c 3 %s | grep -w ttl | wc -l ' % remote_ip
        ping_count = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).communicate()[0].strip()

        msg = 'Host_%s_unreachable' % remote_ip
        if int(ping_count) == 0:
            self.HandleNotification(remote_admin, remote_ip, 'sms', msg)
        elif int(ping_count) < 3:
            self.HandleNotification(remote_admin, remote_ip, 'mail', msg)
        else:
            pass # normal


    def DoMemory(self):
        logging.debug("DoMemory is called")
        total   = subprocess.Popen("free -m |grep Mem |awk '{print $2}'",
                                   shell=True, stdout=subprocess.PIPE).communicate()[0]
        free    = subprocess.Popen("free -m |grep \"buffers/cache\"|awk '{print $4}'",
                                   shell=True, stdout=subprocess.PIPE).communicate()[0]
        total   = float(total.strip())
        free    = float(free.strip())
        
        perc = free * 100 / total
        msg = 'Warn: low mem: %d, total: %d' % (free, total)
        if perc < self._mem_sms or free < 500:
            self.HandleNotification(self._admin, self._host, 'sms', msg)
        elif perc < self._mem_mail:
            self.HandleNotification(self._admin, self._host, 'mail', msg)

    def DoProcess(self):
        logging.debug("DoProcess is called")
        cmd = "ps ax -o pid,user,%%mem,comm,args|awk '{if ($3>%s) print $0}'" % self._process_conf['mem_mail']
        process_list = subprocess.Popen(cmd, shell=True,
                                        stdout=subprocess.PIPE).communicate()[0].split("\n")
        for process_info in process_list:
            item = process_info.strip().split()
            if len(item) < 4:
                continue

            exclude_flag = False
            for exclude in self._process_exclude:
                if re.search(exclude.process, item[4]) == None:
                    continue
                if not (exclude.user == '*' or exclude.user == item[1]):
                    continue
                if float(item[2]) < exclude.mem_mail:
                    continue
                self.ProcessAction(process_info, exclude.mem_kill, exclude.mem_sms, exclude.mem_mail, True)
                exclude_flag = True
                break

            if not exclude_flag:
                self.ProcessAction(process_info, self._process_conf['mem_kill'],
                                   self._process_conf['mem_sms'],
                                   self._process_conf['mem_mail'], False)

    def ProcessAction(self, process_info, mem_kill, mem_sms, mem_mail, skip_flag):
        item = process_info.strip().split()
        info = "process: %s, use mem: %s" % (item[3], item[2])
        alert_to = self._admin + ',' + item[1]
        alert_content = "info: %s" % process_info

        if float(item[2]) > float(mem_kill):
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
            self.HandleNotification(alert_to, self._host, 'sms', msg, alert_content)
        elif float(item[2]) > float(mem_sms):
            if skip_flag:
                msg = "Warn(s): %s" % info
            else:
                msg = "Warn: %s" % info
            self.HandleNotification(alert_to, self._host, 'sms', msg, alert_content)
        else:
            if skip_flag:
                msg = "Info(s): %s" % info
            else:
                msg = "Info: %s" % info
            self.HandleNotification(alert_to, self._host, 'mail', msg, alert_content)

    def DoPing(self):
        logging.debug("DoPing")
        monitor_hosts = []
        for conf in config.hosts:
            if conf['host'] == LOCAL_IP_ADDR:
                continue

            cmd = '/bin/ping -c 3 %s | grep -w ttl | wc -l ' % conf['host']
            logging.debug(cmd)
            remote_admin = ','.join(conf['admin'].split())
            ping_count = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).communicate()[0].strip()

            msg = 'Host_%s_unreachable' % conf['host']
            if int(ping_count) == 0:
                self.DoAlert(remote_admin, conf['host'], 'sms', msg)
            elif int(ping_count) < 3:
                self.DoAlert(remote_admin, conf['host'], 'mail', msg)
            else:
                pass # normal


def usage():
    func_list = []
    prop_list = dir(Host)
    for prop in prop_list:
        if re.search("^Do", prop) != None:
            func_list.append(prop)
    usage_str = "usage: %s  %s" % (sys.argv[0], '|'.join(func_list))
    print usage_str

def do_monitor(method):
    conf = config.build_host(LOCAL_IP_ADDR)
    if not conf:
        print 'host is no configed'
        sys.exit(-1)
    h = Host(conf)
#h.Dump()
    cmd = "h.%s()" % method
    exec cmd

if __name__ == '__main__':
    if len(sys.argv) == 1:
        usage()
    else:
        do_monitor(sys.argv[1])

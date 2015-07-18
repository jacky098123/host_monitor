__author__  = 'Jeff.007.Yang@gmail.com'

# global setting
default_host_config = {
    'host'              : '*',
    'admin'             : '*',
    'mail_notify_all'   : False,
    'sms_notify_all'    : False,
    'notify_skip_user'  : '',
    'disk_mail'         : 90,
    'disk_sms'          : 95,
    'mem_mail'          : 25,
    'mem_sms'           : 20,
    'process_kill'      : 70,
    'process_sms'       : 60,
    'process_mail'      : 50,
    'comment'           : 'default setting',
}

hosts = [
{
    'host'              : '192.168.0.23',
    'admin'             : 'jiemw',
    'mail_notify_all'   : False,
},
{
    'host'              : '192.168.0.24',
    'admin'             : 'jiemw',
    'mail_notify_all'   : False,
},
{
    'host'              : '192.168.0.105',
    'admin'             : 'yangrq zhangchi',
},
]

# global setting
default_process_config = [
{
    'host'      : '*',
    'user'      : '*',
    'process'   : '*',
    'mem_kill'  : 70,
    'mem_sms'   : 60,
    'mem_mail'  : 50,
    'comment'   : 'default setting',
},
{ # concrete host default
    'host'      : '192.168.0.24',
    'user'      : '*',
    'process'   : '*',
    'mem_kill'  : 70,
    'mem_sms'   : 60,
    'mem_mail'  : 50,
    'comment'   : '24 default setting',
},
]

process_excludes = [
{
    'host'      : '*',
    'user'      : '*',
    'process'   : 'mongod',
    'mem_kill'  : 70,
    'mem_sms'   : 70,
    'mem_mail'  : 50,
    'comment'   : 'mongod database'
},
{
    'host'      : '*',
    'user'      : '*',
    'process'   : 'mysql',
    'mem_kill'  : 70,
    'mem_sms'   : 70,
    'mem_mail'  : 50
},
{
    'host'      : '192.168.0.23',
    'user'      : 'yangrq',
    'process'   : 'hotelSearch',
    'mem_kill'  : 70,
    'mem_sms'   : 60,
    'mem_mail'  : 50,
},
{
    'host'      : '192.168.0.24',
    'user'      : '*',
    'process'   : 'hotelSearch',
    'mem_kill'  : 70,
    'mem_sms'   : 60,
    'mem_mail'  : 50,
}
]

def build_host(host_ip):
    host_dict      = None
    for config in hosts:
        if config['host'] == host_ip:
            host_dict = config
            break

    if not host_dict:
        return {}

    if 'comment' in host_dict:
        host_dict.pop('comment')

    host_exclude    = []
    for config in process_excludes:
        if config['host'] in (host_ip , '*'):
            host_exclude.append(config)

    host_dict['process_exclude'] = host_exclude

    return host_dict

if __name__ == '__main__':
    print build_host('192.168.0.24')

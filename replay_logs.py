import timestampExtractor
import os
import time
from glob import glob
from datetime import datetime
import pytz

scenario = 'santos'

if scenario == 'russellmitchell':
    sim_start = datetime.strptime('2022-01-21 00:00:00', '%Y-%m-%d %H:%M:%S') # russellmitchell: 2022-01-24 03:01 - 2022-01-24 04:39
    sim_start = sim_start.replace(tzinfo=pytz.utc)
    sim_end = datetime.strptime('2022-01-25 00:00:00', '%Y-%m-%d %H:%M:%S')
    sim_end = sim_end.replace(tzinfo=pytz.utc)
    logdir = '/home/ubuntu/aitldsv2/russellmitchell/gather/'
elif scenario == 'fox':
    sim_start = datetime.strptime('2022-01-15 00:00:00', '%Y-%m-%d %H:%M:%S') # fox: 2022-01-15 00:00 - 2022-01-20 00:00
    sim_start = sim_start.replace(tzinfo=pytz.utc)
    sim_end = datetime.strptime('2022-01-20 00:00:00', '%Y-%m-%d %H:%M:%S')
    sim_end = sim_end.replace(tzinfo=pytz.utc)
    logdir = '/home/ubuntu/aitldsv2/fox/gather/'
elif scenario == 'harrison':
    sim_start = datetime.strptime('2022-02-04 00:00:00', '%Y-%m-%d %H:%M:%S') # harrison: 2022-02-04 00:00 - 2022-02-09 00:00
    sim_start = sim_start.replace(tzinfo=pytz.utc)
    sim_end = datetime.strptime('2022-02-09 00:00:00', '%Y-%m-%d %H:%M:%S')
    sim_end = sim_end.replace(tzinfo=pytz.utc)
    logdir = '/home/ubuntu/aitldsv2/harrison/gather/'
elif scenario == 'santos':
    sim_start = datetime.strptime('2022-01-14 00:00:00', '%Y-%m-%d %H:%M:%S') # santos: 2022-01-14 00:00 - 2022-01-18 00:00
    sim_start = sim_start.replace(tzinfo=pytz.utc)
    sim_end = datetime.strptime('2022-01-18 00:00:00', '%Y-%m-%d %H:%M:%S')
    sim_end = sim_end.replace(tzinfo=pytz.utc)
    logdir = '/home/ubuntu/aitldsv2/santos/gather/'

output_dir = '/var/log/replay' # Make sure that subdirectories exist
#files = ['/apache2/' + serverName + '-access.log', '/apache2/' + serverName + '-error.log', '/audit/audit.log', '/exim4/mainlog', '/suricata/eve.json', '/suricata/fast.log', '/auth.log', '/daemon.log', '/syslog']

file_keywords = ['/auth.log', '/audit.log', '/suricata.log', '/fast.log', '/eve.json', 'logs/syslog', '/openvpn.log', '/mainlog', '-access.log', '-error.log', '/messages', '/mail.warn', '/mail.info', '/kern.log', '/dnsmasq.log', '/access.log', '/other_vhosts_access.log', '/mail.log', '/user.log', '/daemon.log', '/logstash/internal-share/', '/logstash/intranet-server/'] # '/redis.log', '/redis-server.log', '/stats.log', '.journal', '/error.log']
files = {}
timestamp_mapping = {}
mail_list = []
for fn in os.walk(logdir):
    for filename in glob(os.path.join(fn[0], '*')):
        found = False
        for fk in file_keywords:
            if fk in filename and '~' not in filename:
                timestamp_mapping[filename] = fk
                file_target = filename[filename.find('/gather/') + len('/gather/'):]
                file_ending = file_target.split('.')[-1]
                if file_ending.isdigit():
                    print('Rename ' + file_target)
                    file_target = '.'.join(file_target.split('.')[:-1])
                file_target_parts = file_target.split('/')
                file_target = output_dir + '/'
                for file_target_part in file_target_parts:
                    mail_parts = file_target_part.split('_')
                    if len(mail_parts) > 1 and mail_parts[1] == 'mail':
                        print("Rename " + file_target_part)
                        mail_name = mail_parts[0]
                        if mail_name not in mail_list:
                            mail_list.append(mail_name)
                        file_target_part = "mail" + str(mail_list.index(mail_name))
                    if file_target_part.endswith('-access.log'):
                        print("Rename " + file_target_part)
                        file_target_part = file_target_part.split('.')[0] + '-access.log'
                    if file_target_part.endswith('-error.log'):
                        print("Rename " + file_target_part)
                        file_target_part = file_target_part.split('.')[0] + '-error.log'
                    if file_target_part.startswith('2022-0'):
                        print("Rename " + file_target_part)
                        file_target_part = file_target_part.split('-')[-1]
                        print(file_target_part)
                    file_target += file_target_part + '/'
                files[filename] = file_target[:-1]
                found = True
                break
        #if found is False and 'log' in filename:
        #    print(filename)

if not os.path.isdir(output_dir):
    os.system('sudo mkdir ' + output_dir)
    os.system('sudo chmod --reference=/var/log/syslog ' + output_dir)
    os.system('sudo chown --reference=/var/log/syslog ' + output_dir)
for file in set(files.values()): # Use set to avoid that same files are overwritten multiple times
    current_dir = ""
    for file_part in file.split('/')[:-1]:
        if file_part == '':
            continue
        current_dir += '/' + file_part
        if not os.path.isdir(current_dir):
            print('Create dir ' + current_dir)
            os.system('sudo mkdir ' + current_dir)
            os.system('sudo chmod --reference=/var/log/syslog ' + current_dir)
            os.system('sudo chown --reference=/var/log/syslog ' + current_dir)
    if os.path.isfile(file):
        os.system('sudo rm ' + file)
    print('Create file ' + str(file))
    os.system('sudo touch ' + file)
    os.system('sudo chmod --reference=/var/log/syslog ' + file) # Make sure permissions are correct
    os.system('sudo chown --reference=/var/log/syslog ' + file) # Make sure user and group are correct

inputs = {}
for file in files:
    inputs[file] = open(file, 'r')

outputs = {}
for file in set(files.values()):
    outputs[file] = open(file, 'w+')

currentLines = {}
for file in files:
    currentLines[file] = None

print('Files are ready, press any button to proceed')
input()

print('Starting at ' + str(datetime.now()))
startTime = time.time()
logStartTime = None
while len(currentLines) > 0:
    for file in inputs:
        if file in currentLines and currentLines[file] is None:
            found = False
            while not found:
                logline = None
                try:
                    logline = next(inputs[file])
                except:
                    #print('Remove ' + str(file) + ', ' + str(currentLines.keys()) + ' remain')
                    del currentLines[file]
                    break
                    #continue
                log_time = timestampExtractor.timestampExtractor[timestamp_mapping[file]](logline).timestamp()
                if log_time >= sim_start.timestamp() and log_time <= sim_end.timestamp():
                    currentLines[file] = (logline, log_time)
                    found = True

    if logStartTime is None:
        # Analyze all first lines to find earliest timestamp
        for file in currentLines:
            logline, ts = currentLines[file]
            if logStartTime is None or ts < logStartTime:
                logStartTime = ts

    writtenFiles = []
    for file in currentLines:
        logline, ts = currentLines[file]
        elapsedTime = time.time() - startTime
        if ts <= logStartTime + elapsedTime:
            outputs[files[file]].write(logline)
            outputs[files[file]].flush()
            #print(logline[:-1])
            writtenFiles.append(file)

    for writtenFile in writtenFiles:
        # Clear to get next line in next iteration
        currentLines[writtenFile] = None

print('Done at ' + str(datetime.now()))

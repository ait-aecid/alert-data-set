import json
from datetime import datetime
import pytz
import timestampExtractor
import yaml
from abbrvs import get_short
from attacktimes import get_phase

scenarios = ['fox', 'russellmitchell', 'harrison', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson']
step_size = 3600

counts = {}
all_phases = set()
ips = {}
names = {}
for scenario in scenarios:
    wazuhfile = scenario + '_wazuh.json'
    aminerfile = scenario + '_aminer.json'
    configfile = scenario + '.yaml'
    alertsfile = 'alerts/' + scenario + '_alerts.txt'
    
    with open('alerts_raw/' + wazuhfile) as wazuh_in, open('alerts_raw/' + aminerfile) as aminer_in, open('alerts_sage/' + scenario + '.json', 'w+') as out, open('server_configs/' + configfile) as server_config_file:
        ips[scenario] = {}
        names[scenario] = {}
        server_config = yaml.safe_load(server_config_file)
        mail_cnt = 0
        for hostname in server_config:
            name = hostname
            if hostname.endswith('_mail'):
                name = 'mail' + str(mail_cnt)
                mail_cnt += 1
            ips[scenario][name] = server_config[hostname]['default_ipv4_address']
            names[scenario][server_config[hostname]['default_ipv4_address']] = name
        attacker_ip = server_config['attacker_0']['default_ipv4_address']
        unsorted_alerts = []
        unsorted_ts = []
        for line in wazuh_in:
            j = json.loads(line)
            if 'The average number' in line:
                continue
            if 'data' in j and 'timestamp' in j['data']:
                log_time = datetime.strptime(j['data']['timestamp'], "%Y-%m-%dT%H:%M:%S.%f%z") # 2022-01-21T00:17:54.308261+0000
                log_time = log_time.replace(tzinfo=pytz.utc)
                log_time = log_time.timestamp()
            elif 'predecoder' in j and 'timestamp' in j['predecoder']:
                if '/' in j['predecoder']['timestamp']:
                    log_time = datetime.strptime(j['predecoder']['timestamp'], "%m/%d/%Y-%H:%M:%S.%f") # 01/21/2022-00:17:54.308214
                    log_time = log_time.replace(tzinfo=pytz.utc)
                    log_time = log_time.timestamp()
                else:
                    log_time = datetime.strptime("2022 " + j['predecoder']['timestamp'], "%Y %b %d %H:%M:%S") # Jan 21 01:03:08
                    log_time = log_time.replace(tzinfo=pytz.utc)
                    log_time = log_time.timestamp()
            else:
                if 'full_log' in j:
                    logline = j['full_log']
                else:
                    print(j)
                filename = j['location'].split('/')[-1]
                if filename.endswith('-access.log'):
                    filename = '-access.log'
                elif filename.endswith('-error.log'):
                    filename = '-error.log'
                elif filename.endswith('syslog'):
                    filename = 'logs/syslog'
                else:
                    filename = '/' + filename
                log_time = timestampExtractor.timestampExtractor[filename](logline).timestamp()
            description = j['rule']['description']
            short = get_short(description)
            location = j['agent']['ip']
            srcip = None
            srcport = None
            destip = None
            destport = None
            if "data" in j and "srcip" in j["data"]:
                if ':' in j["data"]["srcip"]:
                    parts = j["data"]["srcip"].split(':')
                    srcip = parts[0]
                    srcport = int(parts[1])
                else:
                    srcip = j["data"]["srcip"]
            elif "data" in j and "src_ip" in j["data"]:
                srcip = j["data"]["src_ip"]
                if "src_ip" in j["data"]:
                    srcport = int(j["data"]["src_port"])
            if "data" in j and "dstip" in j["data"]:
                if ':' in j["data"]["dstip"]:
                    parts = j["data"]["dstip"].split(':')
                    dstip = parts[0]
                    dstport = int(parts[1])
                else:
                    dstip = j["data"]["dstip"]
            elif "data" in j and "dest_ip" in j["data"]:
                destip = j["data"]["dest_ip"]
                if 'dest_port' in j["data"]:
                    destport = int(j["data"]['dest_port'])
            if srcip is None:
                srcip = location
            if destip is None:
                destip = location
            category = None
            if "data" in j and "category" in j["data"]:
                category = j["data"]["category"]
            severity = None
            if "data" in j and "severity" in j["data"]:
                severity = j["data"]["severity"]
            #if not description.startswith('Suricata: '):
            #    description = 'Wazuh: ' + description
            if description.startswith("Suricata: Alert - "):
                description = description[18:]
            if short not in ["W-All-Mul3", "W-Acc-Sus", "W-Acc-Att", "W-Err-Fbd2", "W-Aut-Ssh2", "W-Aut-Uid", "W-Aut-Sud", "W-Err-Fbd1", "A-Aud-Com4", "A-Aud-Com2", "A-Aud-Com6", "A-Acc-Val1", "A-Acc-Ent2", "W-Acc-400", "A-All-Evt", "W-Acc-500", "A-Acc-Val2", "W-Aut-Pam1", "A-Acc-Chr2", "S-Smt-Wel", "S-Smt-Rep", "S-Flw-Nmp", "S-Tls-Ssl", "W-All-Ids", "A-Mon-Avg", "A-Mon-Rng"]:
                continue
            phase = get_phase(scenario, log_time)
            if phase != 'false_positive_same_day' and phase != 'false_positive_other_day' and phase != 'false_positive_test': # and phase != 'dnsteal' and phase != 'service_stop':
                alert = {}
                alert['event_type'] = 'alert'
                alert['host'] = location
                alert['timestamp'] = datetime.fromtimestamp(log_time).strftime('%Y-%m-%dT%H:%M:%S.%f') + '+0000'
                alert['alert'] = {}
                alert['alert']['signature'] = description
                alert['alert']['category'] = category
                alert['alert']['severity'] = severity
                alert['src_ip'] = attacker_ip # srcip
                alert['src_port'] = srcport
                alert['dest_ip'] = ips['fox'][names[scenario][location]] # dstip
                alert['dest_port'] = dstport
                unsorted_alerts.append(alert)
                unsorted_ts.append(log_time)
        for line in aminer_in:
            j = json.loads(line)
            filename = j['LogData']['LogResources'][0].split('/')[-1]
            logline = j['LogData']['RawLogData'][0]
            srcip = None
            if filename.endswith('-access.log'):
                filename = '-access.log'
                srcip = timestampExtractor.ipExtractor[filename](logline)
            else:
                srcip = attacker_ip
            description = j['AnalysisComponent']['AnalysisComponentName']
            short = get_short(description)
            if short not in ["W-All-Mul3", "W-Acc-Sus", "W-Acc-Att", "W-Err-Fbd2", "W-Aut-Ssh2", "W-Aut-Uid", "W-Aut-Sud", "W-Err-Fbd1", "A-Aud-Com4", "A-Aud-Com2", "A-Aud-Com6", "A-Acc-Val1", "A-Acc-Ent2", "W-Acc-400", "A-All-Evt", "W-Acc-500", "A-Acc-Val2", "W-Aut-Pam1", "A-Acc-Chr2", "S-Smt-Wel", "S-Smt-Rep", "S-Flw-Nmp", "S-Tls-Ssl", "W-All-Ids", "A-Mon-Avg", "A-Mon-Rng"]:
                continue
            location = j['AMiner']['ID']
            log_time = j['LogData']['DetectionTimestamp'][-1]
            phase = get_phase(scenario, log_time)
            if phase != 'false_positive_same_day' and phase != 'false_positive_other_day' and phase != 'false_positive_test': # and phase != 'dnsteal' and phase != 'service_stop':
                alert = {}
                alert['event_type'] = 'alert'
                alert['host'] = location
                alert['timestamp'] = datetime.fromtimestamp(log_time).strftime('%Y-%m-%dT%H:%M:%S.%f') + '+0000'
                alert['alert'] = {}
                alert['alert']['signature'] = description
                alert['alert']['category'] = "Anomaly"
                alert['alert']['severity'] = 1
                alert['src_ip'] = attacker_ip # srcip
                alert['src_port'] = None #srcport
                alert['dest_ip'] = ips['fox'][names[scenario][location]] #dstip
                alert['dest_port'] = None #dstport
                unsorted_alerts.append(alert)
                unsorted_ts.append(log_time)
        sorted_alerts = [x for _, _, x in sorted(zip(unsorted_ts, range(len(unsorted_ts)), unsorted_alerts))]
        out.write(json.dumps(list(sorted_alerts)))

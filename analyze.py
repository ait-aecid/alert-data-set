import json
from datetime import datetime
import pytz
import timestampExtractor
import yaml
from abbrvs import get_short
from attacktimes import get_phase, get_duration
import math

scenarios = ['russellmitchell', 'fox', 'harrison', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson']

counts = {}
all_phases = set()
all_descriptions = set()
all_shorts = set()
for scenario in scenarios:
    wazuhfile = scenario + '_wazuh.json'
    aminerfile = scenario + '_aminer.json'
    configfile = scenario + '.yaml'
    alertsfile = 'alerts_csv/' + scenario + '_alerts.txt'
    
    with open('alerts_raw/' + wazuhfile) as wazuh_in, open('alerts_raw/' + aminerfile) as aminer_in, open(alertsfile, 'w+') as alerts_file, open('server_configs/' + configfile) as server_config_file:
        ips = {}
        server_config = yaml.safe_load(server_config_file)
        for hostname in server_config:
            name = hostname
            ips[server_config[hostname]['default_ipv4_address']] = name
        alerts_file.write('time,name,ip,host,short\n')
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
                    print('Unknown alert format: ' + str(j))
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
            all_shorts.add(short)
            if not description.startswith('Suricata: '):
                description = 'Wazuh: ' + description
            all_descriptions.add(description)
            phase = get_phase(scenario, log_time)
            all_phases.add(phase)
            if short not in counts:
                counts[short] = {}
            if phase not in counts[short]:
                counts[short][phase] = {}
            if scenario not in counts[short][phase]:
                counts[short][phase][scenario] = 1
            else:
                counts[short][phase][scenario] += 1
            location = j['agent']['ip']
            alerts_file.write(str(int(log_time)) + ',' + str(description) + ',' + str(location) + ',' + str(ips[location]) + ',' + short + '\n')
        for line in aminer_in:
            j = json.loads(line)
            log_time = j['LogData']['DetectionTimestamp'][-1]
            description = j['AnalysisComponent']['AnalysisComponentName']
            all_descriptions.add(description)
            location = j['AMiner']['ID']
            short = get_short(description)
            all_shorts.add(short)
            phase = get_phase(scenario, log_time)
            all_phases.add(phase)
            if short not in counts:
                counts[short] = {}
            if phase not in counts[short]:
                counts[short][phase] = {}
            if scenario not in counts[short][phase]:
                counts[short][phase][scenario] = 1
            else:
                counts[short][phase][scenario] += 1
            alerts_file.write(str(int(log_time)) + ',' + str(description) + ',' + str(location) + ',' + str(ips[location]) + ',' + short + '\n')

s = "& "
all_phases_list = ['network_scans', 'service_scans', 'wpscan', 'dirb', 'webshell', 'cracking', 'reverse_shell', 'privilege_escalation', 'service_stop', 'dnsteal', 'false_positive_test']
for phase in all_phases_list:
    s += phase.replace('_', '\_') + ' & '
s += "robustness & detection \\\\ \hline \n"
unsorted = {}
for short, d in counts.items():
    s_tmp = short + ' & '
    max_score_result1 = 0
    max_score_result2 = 0
    for phase in all_phases_list:
        if phase in d:
            s_tmp += str(len(d[phase])) + ' & '
            if phase == 'false_positive_test':
                continue
            scores = []
            for scenario in d[phase]:
                alerts_per_second_attack = d[phase][scenario] / get_duration(scenario, phase)
                fp = 0
                score = 1
                if 'false_positive_test' in d and scenario in d['false_positive_test']:
                    fp = d['false_positive_test'][scenario]
                    score = 1 - min(1, fp / (alerts_per_second_attack * get_duration(scenario, 'false_positive_test'))) # get_attack_free_duration(scenario)))
                scores.append(score)
                #if short == "S-Htt-Mat":
                #    print(short + ': ' + phase + ': ' + scenario + ': ' + str(d[phase][scenario]) + ' occurred in ' + str(get_duration(scenario, phase)) + ' seconds, expect ' + str(alerts_per_second_attack * get_duration(scenario, 'false_positive_test')) + ' in ' + str(get_duration(scenario, 'false_positive_test')) + ' seconds but is ' + str(str(fp)) + ', score is ' + str(score))
            #print(short + ': ' + phase + ': ' + str(scores))
            score_result1 = sum(scores) / len(scores)
            total_datasets = 8.0
            if phase == "cracking":
                # Cracking does not occur in wheeler scenario
                total_datasets = 7.0
            score_result2 = sum(scores) / total_datasets # Note that len(scores) cancels out
            if score_result2 > max_score_result2:
                max_score_result1 = score_result1
                max_score_result2 = score_result2
        else:
            s_tmp += '  & '
    s_tmp += str(round(max_score_result1, 2))
    s_tmp += " & " + str(round(max_score_result2, 2))
    s_tmp += ' \\\\ \hline'
    unsorted[s_tmp] = max_score_result2
dict_sorted = dict(sorted(unsorted.items(), key=lambda item: item[1], reverse=True))
print(s)
for key in dict_sorted:
    print(key)

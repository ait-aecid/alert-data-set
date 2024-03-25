import json
from datetime import datetime
from datetime import timezone
import pytz
import timestampExtractor
import yaml
from abbrvs import get_short
from attacktimes import get_phase, get_duration
import math
import glob
import re

def get_ts_label(label):
    # Events in the AIT-LDSv2 sometimes have multiple labels; this function only returns a single label that we consider the most descriptive one
    if len(label) == 1:
        return label[0]
    keywords = ['wpscan', 'dirb', 'dnsteal', 'dns_scan', 'service_scan', 'attacker_change_user', 'escalated_sudo_command', 'webshell_cmd', 'crack_passwords']
    for keyword in keywords:
        if keyword in label:
            return keyword
    print('Unknown label: ' + label)

def get_labels(scenario, aitlds_path, path):
    # Return labels for log events
    for glob_path in glob.glob(aitlds_path + '/' + scenario + '/labels' + path):
        with open(glob_path) as label_file, open(glob_path.replace('/labels/', '/gather/')) as log_file:
            lines_labels = {}
            for line in label_file:
                j = json.loads(line)
                lines_labels[j['line']] = j['labels']
            final_labels = {}
            line_count = 0
            for line in log_file:
                line = line.strip('\n\r ')
                line_count += 1
                if line_count in lines_labels:
                    if line in final_labels and final_labels[line] != lines_labels[line_count]:
                        print('Duplicated line with labels ' + str(final_labels[line]) + ' and ' + str(lines_labels[line_count]) + ': ' + line)
                    final_labels[line] = lines_labels[line_count]
            return final_labels

def get_eve_labels(scenario, aitlds_path, path):
    # Return labels for data exfiltration alerts
    for glob_path in glob.glob(aitlds_path + '/' + scenario + '/labels' + path):
        with open(glob_path) as label_file, open(glob_path.replace('/labels/', '/gather/')) as log_file:
            lines_labels = {}
            for line in label_file:
                j = json.loads(line)
                lines_labels[j['line']] = j['labels']
            final_labels = {}
            line_count = 0
            for line in log_file:
                line_count += 1
                search_result = None
                for regex in [" query[A] (.+?) from ", " forwarded (.+?) to ", " reply (.+?) is "]:
                    search_result = re.search(regex, line)
                    if search_result:
                        break
                if search_result:
                    rrname = search_result.group(1)
                else:
                    continue
                if line_count in lines_labels:
                    final_labels[rrname] = lines_labels[line_count]
            return final_labels

def netflow_label_mapping(label):
    if label == '-':
        return label
    elif label in ["browsing/update", "benign_share", "proxy", "SSH", "mail", "update/command on unassigned port", "DNS", "monitoring", "HTTP(S) intra", "HTTP", "HTTPS", "HTTP(S) DMZ", "broken flow - benign"]:
        # Normal behavior
        return None
    elif label == "data exfiltration":
        return "dnsteal"
    elif label == "online_cracking":
        return "crack_passwords"
    elif label == 'service_scan':
        return label
    else:
        print('Unknown label: ' + label)

def get_netflows(scenario, aitnds_path):
    # Return labels for netflows
    # Requires that AIT-NDS files (tcp_complete.csv, tcp_nocomplete.csv, and udp_complete.csv) are available
    with open(aitnds_path + '/' + scenario + '_netflows/tcp_complete.csv') as tcp_comp, open(aitnds_path + '/' + scenario + '_netflows/tcp_nocomplete.csv') as tcp_no, open(aitnds_path + '/' + scenario + '_netflows/udp_complete.csv') as udp:
        header = True
        cols = None
        final_labels = {}
        for line in udp:
            line = line.strip('\n\r ')
            if header is True:
                header = False
                cols = line.split(',')
                continue
            parts = line.split(',')
            proto = "UDP"
            cip = parts[cols.index('#c_ip:1')]
            cport = parts[cols.index('c_port:2')]
            srcip = parts[cols.index('s_ip:10')]
            srcport = parts[cols.index('s_port:11')]
            time = float(parts[cols.index('c_first_abs:3')])
            while time > 10000000000:
                time /= 10
            label = parts[cols.index('label')]
            if label == "data exfiltration":
                if (proto, cip, cport, srcip, srcport) not in final_labels:
                    final_labels[(proto, cip, cport, srcip, srcport)] = [(time, label)]
                else:
                    final_labels[(proto, cip, cport, srcip, srcport)].append((time, label))
        header = True
        cols = None
        for line in tcp_comp:
            line = line.strip('\n\r ')
            if header is True:
                header = False
                cols = line.split(',')
                continue
            parts = line.split(',')
            proto = "TCP"
            cip = parts[cols.index('#15#c_ip:1')]
            cport = parts[cols.index('c_port:2')]
            srcip = parts[cols.index('s_ip:15')]
            srcport = parts[cols.index('s_port:16')]
            time = float(parts[cols.index('first:29')])
            while time > 10000000000:
                time /= 10
            label = parts[cols.index('label')]
            if label.startswith("check_") or label.startswith("read_") or label.startswith("list_"):
                label = "command"
            if label not in ["browsing/update", "benign_share", "proxy", "SSH", "mail", "update/command on unassigned port", "DNS", "monitoring", "HTTP(S) intra", "HTTP", "HTTPS", "HTTP(S) DMZ"]:
                if (proto, cip, cport, srcip, srcport) not in final_labels:
                    final_labels[(proto, cip, cport, srcip, srcport)] = [(time, label)]
                else:
                    final_labels[(proto, cip, cport, srcip, srcport)].append((time, label))
        header = True
        cols = None
        for line in tcp_no:
            line = line.strip('\n\r ')
            if header is True:
                header = False
                cols = line.split(',')
                continue
            parts = line.split(',')
            proto = "TCP"
            cip = parts[cols.index('#15#c_ip:1')]
            cport = parts[cols.index('c_port:2')]
            srcip = parts[cols.index('s_ip:15')]
            srcport = parts[cols.index('s_port:16')]
            time = float(parts[cols.index('first:29')])
            while time > 10000000000:
                time /= 10
            label = parts[cols.index('label')]
            if label not in ["broken flow - benign"]:
                if (proto, cip, cport, srcip, srcport) not in final_labels:
                    final_labels[(proto, cip, cport, srcip, srcport)] = [(time, label)]
                else:
                    final_labels[(proto, cip, cport, srcip, srcport)].append((time, label))
        return final_labels

scenarios = ['russellmitchell', 'fox', 'harrison', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson']
aitlds_path = '/home/ubuntu/aitldsv2'
aitnds_path = '/home/ubuntu/aitnds'
do_event_labeling = False # If set to True, the log data set from the AIT-LDSv2 for the respective scenarios must be available in aitlds_path and the AIT-NDS must be available in aitnds_path

counts = {}
all_phases = set()
all_descriptions = set()
all_shorts = set()
for scenario in scenarios:
    print('Processing scenario ' + scenario)
    wazuhfile = scenario + '_wazuh.json'
    aminerfile = scenario + '_aminer.json'
    configfile = scenario + '.yaml'
    alertsfile = 'alerts_csv/' + scenario + '_alerts.txt'

    if do_event_labeling:
        print(' Reading labels...')
        labels = {}
        labels[('/var/log/dnsmasq.log', 'inet-firewall')] = get_labels(scenario, aitlds_path, '/inet-firewall/logs/dnsmasq.log')
        labels[('/var/log/apache2/intranet-access.log', 'intranet_server')] = get_labels(scenario, aitlds_path, '/intranet_server/logs/apache2/intranet.*-access.log*')
        labels[('/var/log/apache2/intranet-error.log', 'intranet_server')] = get_labels(scenario, aitlds_path, '/intranet_server/logs/apache2/intranet.*-error.log*')
        labels[('/var/log/audit/audit.log', 'internal_share')] = get_labels(scenario, aitlds_path, '/internal_share/logs/audit/audit.log')
        labels[('/var/log/audit/audit.log', 'intranet_server')] = get_labels(scenario, aitlds_path, '/intranet_server/logs/audit/audit.log')
        labels[('/var/log/auth.log', 'intranet_server')] = get_labels(scenario, aitlds_path, '/intranet_server/logs/auth.log*')
        if scenario == 'wheeler':
            labels[('/var/log/logstash/intranet-server/system.cpu.log', 'monitoring')] = []
        else:
            labels[('/var/log/logstash/intranet-server/system.cpu.log', 'monitoring')] = get_labels(scenario, aitlds_path, '/monitoring/logs/logstash/intranet-server/*-system.cpu.log')
        labels[('/var/log/openvpn.log', 'vpn')] = get_labels(scenario, aitlds_path, '/vpn/logs/openvpn.log')
        # Due to missing labels in netflow logs, labels for eve.json are derived from DNS logs
        labels[('/var/log/suricata/eve.json', 'inet-firewall')] = get_eve_labels(scenario, aitlds_path, '/inet-firewall/logs/dnsmasq.log')
        labels[('/var/log/suricata/eve.json', 'internal_share')] = get_eve_labels(scenario, aitlds_path, '/inet-firewall/logs/dnsmasq.log')
        #for k, v in labels.items():
        #    print(k)
        #    print(str(k) + ': ' + str(len(v)))
        netflows = get_netflows(scenario, aitnds_path)
   
    print(' Processing log files...')
    with open('alerts_raw/' + wazuhfile) as wazuh_in, open('alerts_raw/' + aminerfile) as aminer_in, open(alertsfile, 'w+') as alerts_file, open('server_configs/' + configfile) as server_config_file:
        ips = {}
        server_config = yaml.safe_load(server_config_file)
        for hostname in server_config:
            name = hostname
            ips[server_config[hostname]['default_ipv4_address']] = name
        alerts_file.write('time,name,ip,host,short,time_label,event_label\n')
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
            event_label = '-'
            if do_event_labeling:
                if 'full_log' in j:
                    # Check if the line appears in the label file; if yes, assign the corresponding label
                    log_line_from_alert = j['full_log']
                    if 'audit' in j['location']:
                        # Wazuh aggregates multiple audit lines into one, needs to be split
                        parts = log_line_from_alert.split('type=')
                        log_line_from_alert_list = ['type=' + part for part in parts if part != '']
                    else:
                        log_line_from_alert_list = [log_line_from_alert]
                    file_name_from_alert = (j['location'], ips[j['agent']['ip']])
                    if file_name_from_alert in labels:
                        for log_line_from_alert in log_line_from_alert_list:
                            if log_line_from_alert in labels[file_name_from_alert]:
                                event_label = labels[file_name_from_alert][log_line_from_alert]
                                break
                elif description.startswith('Suricata: '):
                    if description == "Suricata: Alert - ET INFO Observed DNS Query to .biz TLD" and (scenario == "harrison" or scenario == "santos"): # DNSteal domain with .biz TLD only in harrison and santos
                        # Alerts of this type are (incorrectly) not labeled in the netflows; thus, labeling is based on (correctly) labeled dnsmasq logs
                        if len(j['data']['dns']['query']) > 1:
                            print('Multiple rrname entries in alert: ' + str(j['data']['dns']['query']))
                        rrname = j['data']['dns']['query'][0]['rrname']
                        file_name_from_alert = (j['location'], ips[j['agent']['ip']])
                        if file_name_from_alert in labels:
                            if rrname in labels[file_name_from_alert]:
                                event_label = labels[file_name_from_alert][rrname]
                    else:
                        # Check if the netflow attributes correspond to a labeled netflow in the AIT-NDS; if yes, assign the corresponding label
                        proto = j['data']['proto']
                        srcip = j['data']['src_ip']
                        srcport = j['data']['src_port']
                        destip = j['data']['dest_ip']
                        destport = j['data']['dest_port']
                        if (proto, srcip, srcport, destip, destport) in netflows:
                            alert_time = datetime.strptime(j['data']['timestamp'], "%Y-%m-%dT%H:%M:%S.%f+0000").replace(tzinfo=timezone.utc).timestamp() # "2022-01-24T03:57:01.687867+0000"
                            for netflow_time, netflow_label in netflows[(proto, srcip, srcport, destip, destport)]:
                                if abs(alert_time - netflow_time) < 2:
                                    event_label = [netflow_label]
                                    break
                        if (proto, destip, destport, srcip, srcport) in netflows:
                            alert_time = datetime.strptime(j['data']['timestamp'], "%Y-%m-%dT%H:%M:%S.%f+0000").replace(tzinfo=timezone.utc).timestamp() # "2022-01-24T03:57:01.687867+0000"
                            for netflow_time, netflow_label in netflows[(proto, destip, destport, srcip, srcport)]:
                                if abs(alert_time - netflow_time) < 2:
                                    event_label = [netflow_label]
                                    break
                else:
                    print('full_log missing from alert: ' + str(j))
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
            time_label = phase
            if time_label.startswith('false_positive'):
                time_label = 'false_positive'
            event_label = get_ts_label(event_label)
            alerts_file.write(str(int(log_time)) + ',' + str(description) + ',' + str(location) + ',' + str(ips[location]) + ',' + short + ',' + time_label + ',' + event_label + '\n')
        for line in aminer_in:
            j = json.loads(line)
            log_time = j['LogData']['DetectionTimestamp'][-1]
            description = j['AnalysisComponent']['AnalysisComponentName']
            all_descriptions.add(description)
            location = j['AMiner']['ID']
            short = get_short(description)
            all_shorts.add(short)
            log_line_from_alert = j['LogData']['RawLogData'][0]
            file_name_from_alert = (j['LogData']['LogResources'][0], ips[j['AMiner']['ID']])
            event_label = "-"
            if do_event_labeling:
                if file_name_from_alert in labels:
                    if log_line_from_alert in labels[file_name_from_alert]:
                        event_label = labels[file_name_from_alert][log_line_from_alert]
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
            time_label = phase
            if time_label.startswith('false_positive'):
                time_label = 'false_positive'
            event_label = get_ts_label(event_label)
            alerts_file.write(str(int(log_time)) + ',' + str(description) + ',' + str(location) + ',' + str(ips[location]) + ',' + short + ',' + time_label + ',' + event_label + '\n')

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

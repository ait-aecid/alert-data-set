import json
from datetime import datetime
import pytz
import timestampExtractor
import yaml
from abbrvs import get_short
from attacktimes import get_phase

scenarios = ['russellmitchell', 'fox', 'harrison', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson']
select_abbrvs = ["W-All-Mul3", "W-Acc-Sus", "W-Acc-Att", "W-Err-Fbd2", "W-Aut-Ssh2", "W-Aut-Uid", "W-Aut-Sud", "W-Err-Fbd1", "A-Aud-Com4", "A-Aud-Com2", "A-Aud-Com6", "A-Acc-Val1", "A-Acc-Ent2", "W-Acc-400", "A-All-Evt", "W-Acc-500", "A-Acc-Val2", "W-Aut-Pam1", "A-Acc-Chr2", "S-Smt-Wel", "S-Smt-Rep", "S-Flw-Nmp", "S-Tls-Ssl", "W-All-Ids", "A-Mon-Avg", "A-Mon-Rng"]

for scenario in scenarios:
    wazuhfile = scenario + '_wazuh.json'
    aminerfile = scenario + '_aminer.json'
    configfile = scenario + '.yaml'
    
    with open('alerts_raw/' + wazuhfile) as wazuh_in, open('alerts_raw/' + aminerfile) as aminer_in, open('alerts_filtered/' + wazuhfile, 'w+') as wazuh_out, open('alerts_filtered/' + aminerfile, 'w+') as aminer_out:
        # WAZUH ALERTS
        lines = []
        times = []
        for line in wazuh_in:
            j = json.loads(line)
            # Filter alerts that are not in select_abbrvs
            description = j['rule']['description']
            short = get_short(description)
            if short not in select_abbrvs:
                continue
            # Get timestamp from alerts (each field has different timestamp formats)
            if 'data' in j and 'timestamp' in j['data']:
                log_time = datetime.strptime(j['data']['timestamp'], "%Y-%m-%dT%H:%M:%S.%f%z").replace(tzinfo=pytz.utc).timestamp() # 2022-01-21T00:17:54.308261+0000
            elif 'predecoder' in j and 'timestamp' in j['predecoder']:
                if '/' in j['predecoder']['timestamp']:
                    log_time = datetime.strptime(j['predecoder']['timestamp'], "%m/%d/%Y-%H:%M:%S.%f").replace(tzinfo=pytz.utc).timestamp() # 01/21/2022-00:17:54.308214
                else:
                    log_time = datetime.strptime("2022 " + j['predecoder']['timestamp'], "%Y %b %d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() # Jan 21 01:03:08
            else:
                if 'full_log' in j:
                    logline = j['full_log']
                else:
                    print('Alerts is missing full_log field: ' + str(j))
                filename = j['location'].split('/')[-1]
                # Normalize file names that have scenario names in them
                if filename.endswith('-access.log'):
                    filename = '-access.log'
                elif filename.endswith('-error.log'):
                    filename = '-error.log'
                elif filename.endswith('syslog'):
                    filename = 'logs/syslog'
                else:
                    filename = '/' + filename
                log_time = timestampExtractor.timestampExtractor[filename](logline).timestamp()
            # Filter alerts that occur outside of attack phases
            phase = get_phase(scenario, log_time)
            if phase != 'false_positive_same_day' and phase != 'false_positive_other_day' and phase != 'false_positive_test':
                lines.append(line)
                times.append(log_time)
        # Sort alerts and write to output file
        for line in [x for _, x in sorted(zip(times, lines))]:
            wazuh_out.write(line)
        # AMINER ALERTS
        lines = []
        times = []
        for line in aminer_in:
            j = json.loads(line)
            # Filter alerts that are not in select_abbrvs
            description = j['AnalysisComponent']['AnalysisComponentName']
            short = get_short(description)
            if short not in select_abbrvs:
                continue
            log_time = j['LogData']['DetectionTimestamp'][-1]
            # Filter alerts that occur outside of attack phases
            phase = get_phase(scenario, log_time)
            if phase != 'false_positive_same_day' and phase != 'false_positive_other_day' and phase != 'false_positive_test':
                lines.append(line)
                times.append(log_time)
        # Filter alerts that occur outside of attack phases
        for line in [x for _, x in sorted(zip(times, lines))]:
            aminer_out.write(line)

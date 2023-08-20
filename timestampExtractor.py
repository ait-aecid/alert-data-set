import datetime
import pytz
from dateutil import parser
import json

def getAuditTimestamp(line):
  parts = line.split(' ')
  timestamp = None
  if len(parts) > 1:
    innerParts = parts[1].split('.')
    timestamp = datetime.datetime.utcfromtimestamp(int(innerParts[0][10:]))
    timestamp = timestamp.replace(tzinfo=pytz.utc)
  return timestamp

def removeAuditTimestamp(line):
  result = ''
  skip = False
  i = 0
  for char in line:
    if char == '(':
      result += char
      skip = True
    elif char == ')':
      result += line[i:]
      break
    elif skip == False:
      result += char  
    i += 1
  return result

def getEximTimestamp(line):
  parts = line.split(' ')
  timestamp = None
  if len(parts) > 1:
    timestamp = datetime.datetime.strptime(parts[0] + ' ' + parts[1], '%Y-%m-%d %H:%M:%S')
    timestamp = timestamp.replace(tzinfo=pytz.utc)
  return timestamp

def removeEximTimestamp(line):
  return line[20:]

def getSyslogTimestamp(line):
  timestamp = None
  if len(line) > 15:
      timestamp = datetime.datetime.strptime("2022 " + line[:15], '%Y %b %d %H:%M:%S') # TODO be aware: syslog has no year, thus %Y is hardcoded!
      timestamp = timestamp.replace(tzinfo=pytz.utc)
  return timestamp

def removeSyslogTimestamp(line):
  return line[16:]

def getJsonTimestamp(line):
  timestamp = None
  if len(line) > 45:
      timestamp = datetime.datetime.strptime(line[14:45], '%Y-%m-%dT%H:%M:%S.%f%z') #parser.parse(line[14:45])
  return timestamp

def removeJsonTimestamp(line):
  return line[:14] + line[45:]

def getFastTimestamp(line):
  timestamp = None
  if len(line) > 26:
      timestamp = datetime.datetime.strptime(line[:26], '%m/%d/%Y-%H:%M:%S.%f') #parser.parse(line[:26])
      timestamp = timestamp.replace(tzinfo=pytz.utc)
  return timestamp

def removeFastTimestamp(line):
  return line[28:]

def getAccessTimestamp(line):
  parts = line.split(' ')
  timestamp = None
  if len(parts) > 4:
      if parts[3][0] == '[':
          timestamp = datetime.datetime.strptime(parts[3][1:] + ' ' + parts[4][:-1], '%d/%b/%Y:%H:%M:%S %z')
      else:
          timestamp = datetime.datetime.strptime(parts[4][1:] + ' ' + parts[5][:-1], '%d/%b/%Y:%H:%M:%S %z')
  return timestamp

def removeAccessTimestamp(line):
  parts = line.split(' ')
  parts[3] = ''
  return ' '.join(parts)

def getAccessIp(line):
  return line.split(' ')[0]

def getErrorTimestamp(line):
  timestamp = None
  if len(line) > 32:
      timestamp = datetime.datetime.strptime(line[5:32], '%b %d %H:%M:%S.%f %Y') #parser.parse(line[1:32])
      timestamp = timestamp.replace(tzinfo=pytz.utc)
  return timestamp

def removeErrorTimestamp(line):
  return '[' + line[32:]

def getSuricataTimestamp(line):
    parts = line.split(' ')
    return datetime.datetime.strptime(parts[0] + ' ' + parts[2], '%d/%m/%Y %H:%M:%S')

def getMonitoringTimestamp(line):
    j = json.loads(line)
    timestamp = datetime.datetime.strptime(j['@timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
    timestamp = timestamp.replace(tzinfo=pytz.utc)
    return timestamp

#['/auth.log'] #, '/audit.log', '/suricata.log', '/fast.log', '/stats.log', '/eve.json', '/core', 'logs/syslog', '/openvpn.log', '.journal', '/mainlog', '-access.log', '-error.log', '/messages', '/mail.warn', '/mail.info', '/kern.log', '/dnsmasq.log', '/access.log', '/error.log', '/other_vhosts_access.log', '/mail.log', '/user.log', '/redis.log', '/redis-server.log']

timestampExtractor = {
'/audit.log': getAuditTimestamp,
'/auth.log': getSyslogTimestamp,
'/mail.log': getSyslogTimestamp,
'/mail.info': getSyslogTimestamp,
'/mail.warn': getSyslogTimestamp,
'/mainlog': getEximTimestamp,
'/messages': getSyslogTimestamp,
'/eve.json': getJsonTimestamp,
'/fast.log': getFastTimestamp,
'/daemon.log': getSyslogTimestamp,
'logs/syslog': getSyslogTimestamp,
'/user.log': getSyslogTimestamp,
'-access.log': getAccessTimestamp,
'-error.log': getErrorTimestamp,
'/suricata.log': getSuricataTimestamp,
'/openvpn.log': getEximTimestamp,
'/kern.log': getSyslogTimestamp,
'/dnsmasq.log': getSyslogTimestamp,
'/access.log': getAccessTimestamp,
'/error.log': getErrorTimestamp,
'/other_vhosts_access.log': getAccessTimestamp,
'/logstash/internal-share/': getMonitoringTimestamp,
'/logstash/intranet-server/': getMonitoringTimestamp,
}

ipExtractor = {
'-access.log': getAccessIp,
'/access.log': getAccessIp,
'/other_vhosts_access.log': getAccessIp,
}

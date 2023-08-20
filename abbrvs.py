def get_short(description):
    short = None
    if description == "AMiner: CPU value deviates from average in monitoring logs.":
        short="A-Mon-Avg"
    if description == "AMiner: CPU value out of expected range in monitoring logs.":
        short="A-Mon-Rng"
    if description == "AMiner: High entropy in Apache Access referer.":
        short="A-Acc-Ent1"
    if description == "AMiner: High entropy in Apache Access request.":
        short="A-Acc-Ent2"
    if description == "AMiner: High entropy in Apache Access user agent.":
        short="A-Acc-Ent3"
    if description == "AMiner: High entropy in DNS domain.":
        short="A-Dns-Ent"
    if description == "AMiner: New apparmor parameter combination in Audit logs.":
        short="A-Aud-Com1"
    if description == "AMiner: New characters in Apache Access referer.":
        short="A-Acc-Chr1"
    if description == "AMiner: New characters in Apache Access request.":
        short="A-Acc-Chr2"
    if description == "AMiner: New characters in DNS domain.":
        short="A-Dns-Chr"
    if description == "AMiner: New cred_acq parameter combination in Audit logs.":
        short="A-Aud-Com2"
    if description == "AMiner: New cred_disp parameter combination in Audit logs.":
        short="A-Aud-Com2"
    if description == "AMiner: New cred_refr parameter combination in Audit logs.":
        short="A-Aud-Com2"
    if description == "AMiner: New event type.":
        short="A-All-Evt"
    if description == "AMiner: New ip address in DNS logs.":
        short="A-Dns-Val1"
    if description == "AMiner: New login parameter combination in Audit logs.":
        short="A-Aud-Com3"
    if description == "AMiner: New query record in DNS logs.":
        short="A-Dns-Val2"
    if description == "AMiner: New request method in Apache Access log.":
        short="A-Acc-Val1"
    if description == "AMiner: New service_start parameter combination in Audit logs.":
        short="A-Aud-Com4"
    if description == "AMiner: New service_stop parameter combination in Audit logs.":
        short="A-Aud-Com4"
    if description == "AMiner: New status code in Apache Access log.":
        short="A-Acc-Val2"
    if description == "AMiner: New syscall parameter combination in Audit logs.":
        short="A-Aud-Com5"
    if description == "AMiner: New user_acct parameter combination in Audit logs.":
        short="A-Aud-Com6"
    if description == "AMiner: New user_auth parameter combination in Audit logs.":
        short="A-Aud-Com6"
    if description == "AMiner: New user_cmd parameter combination in Audit logs.":
        short="A-Aud-Com6"
    if description == "AMiner: New user_end parameter combination in Audit logs.":
        short="A-Aud-Com6"
    if description == "AMiner: New user_login parameter combination in Audit logs.":
        short="A-Aud-Com6"
    if description == "AMiner: New user_start parameter combination in Audit logs.":
        short="A-Aud-Com6"
    if description == "AMiner: Unusual occurrence frequencies of Apache Access logs.":
        short="A-Acc-Frq"
    if description == "AMiner: Unusual occurrence frequencies of Apache Access request methods.":
        short="A-Acc-Clc"
    if description == "AMiner: Unusual occurrence frequencies of DNS log events.":
        short="A-Dns-Clc1"
    if description == "AMiner: Unusual occurrence frequencies of DNS query IPs.":
        short="A-Dns-Clc2"
    if description == "AMiner: Unusual occurrence frequencies of DNS query records.":
        short="A-Dns-Clc3"
    if description == "AMiner: Unusual occurrence frequencies of query records in DNS logs.":
        short="A-Dns-Frq"
    if description == "Suricata: Alert - ET DNS DNS Lookup for localhost.DOMAIN.TLD":
        short="S-Dns-Loo"
    if description == "Suricata: Alert - ET DNS Query for .cc TLD":
        short="S-Dns-Qry1"
    if description == "Suricata: Alert - ET DNS Query for .su TLD (Soviet Union) Often Malware Related":
        short="S-Dns-Qry1"
    if description == "Suricata: Alert - ET DNS Query for .to TLD":
        short="S-Dns-Qry1"
    if description == "Suricata: Alert - ET DNS Query to a *.pw domain - Likely Hostile":
        short="S-Dns-Qry1"
    if description == "Suricata: Alert - ET HUNTING Possible COVID-19 Domain in SSL Certificate M2":
        short="S-Flw-Cov"
    if description == "Suricata: Alert - ET HUNTING Suspicious Domain Request for Possible COVID-19 Domain M1":
        short="S-Flw-Cov"
    if description == "Suricata: Alert - ET HUNTING Suspicious TLS SNI Request for Possible COVID-19 Domain M1":
        short="S-Flw-Cov"
    if description == "Suricata: Alert - ET INFO DNS Query for Suspicious .ga Domain":
        short="S-Dns-Qry2"
    if description == "Suricata: Alert - ET INFO Observed DNS Query to .biz TLD":
        short="S-Dns-Qry3"
    if description == "Suricata: Alert - ET INFO TLS Handshake Failure":
        short="S-Tls-Fai"
    if description == "Suricata: Alert - ET INFO Observed DNS Query to .cloud TLD":
        short="S-Dns-Qry4"
    if description == "Suricata: Alert - ET INFO Session Traversal Utilities for NAT (STUN Binding Request)":
        short="S-Nat-Trv"
    if description == "Suricata: Alert - ET INFO Session Traversal Utilities for NAT (STUN Binding Response)":
        short="S-Nat-Trv"
    if description == "Suricata: Alert - ET INFO Suspicious Domain (*.ga) in TLS SNI":
        short="S-Dns-Dom"
    if description == "Suricata: Alert - ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management":
        short="S-Flw-Apt"
    if description == "Suricata: Alert - ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection":
        short="S-Flw-445"
    if description == "Suricata: Alert - ET SCAN Possible Nmap User-Agent Observed":
        short="S-Flw-Nmp"
    if description == "Suricata: Alert - SURICATA DNS Unsolicited response":
        short="S-Dns-Uns"
    if description == "Suricata: Alert - SURICATA HTTP gzip decompression failed":
        short="S-Htt-Gzp"
    if description == "Suricata: Alert - SURICATA HTTP invalid response chunk len":
        short="S-Htt-Res"
    if description == "Suricata: Alert - SURICATA HTTP unable to match response to request":
        short="S-Htt-Mat"
    if description == "Suricata: Alert - SURICATA SMTP invalid reply":
        short="S-Smt-Rep"
    if description == "Suricata: Alert - SURICATA SMTP no server welcome message":
        short="S-Smt-Wel"
    if description == "Suricata: Alert - SURICATA TLS certificate invalid der":
        short="S-Tls-Crt"
    if description == "Suricata: Alert - SURICATA TLS invalid handshake message":
        short="S-Tls-Hnd"
    if description == "Suricata: Alert - SURICATA TLS invalid record/traffic":
        short="S-Tls-Rec"
    if description == "Suricata: Alert - SURICATA TLS invalid record type":
        short="S-Tls-Typ"
    if description == "Suricata: Alert - SURICATA TLS invalid SSLv2 header":
        short="S-Tls-Ssl"
    if description == "Apache: Attempt to access forbidden directory index.":
        short="W-Err-Fbd1"
    if description == "Apache: Attempt to access forbidden file or directory.":
        short="W-Err-Fbd2"
    if description == "Auditd: SELinux permission check.":
        short="W-Aud-Sel"
    if description == "ClamAV database update":
        short="W-Sys-Cav"
    if description == "CMS (WordPress or Joomla) login attempt.":
        short="W-Acc-Cms"
    if description == "CMS (WordPress or Joomla) brute force attempt.":
        short="W-Acc-Brt"
    if description == "Common web attack.":
        short="W-Acc-Att"
    if description == "Dovecot Authentication Success.":
        short="W-Sys-Dov"
    if description == "Dovecot brute force attack (multiple auth failures).":
        short="W-Mai-Brt"
    if description == "Dovecot Invalid User Login Attempt.":
        short="W-Mai-Inv"
    if description == "First time this IDS alert is generated.":
        short="W-All-Ids"
    if description == "First time user executed sudo.":
        short="W-Aut-Sud"
    if description == "IDS event.":
        short="W-All-Evt"
    if description == "Multiple IDS alerts for same id (ignoring now this id).":
        short="W-All-Mul1"
    if description == "Multiple IDS alerts for same id.":
        short="W-All-Mul1"
    if description == "Multiple IDS events from same source ip.":
        short="W-All-Mul2"
    if description == "Multiple IDS events from same source ip (ignoring now this srcip and id).":
        short="W-All-Mul2"
    if description == "Multiple web server 400 error codes from same source ip.":
        short="W-All-Mul3"
    if description == "PAM: Login session closed.":
        short="W-Aut-Pam1"
    if description == "PAM: Login session opened.":
        short="W-Aut-Pam1"
    if description == "PAM: Multiple failed logins in a small period of time.":
        short="W-Aut-Pam3"
    if description == "PAM: User login failed.":
        short="W-Aut-Pam2"
    if description == "sshd: authentication success.":
        short="W-Aut-Ssh1"
    if description == "sshd: insecure connection attempt (scan).":
        short="W-Aut-Ssh2"
    if description == "Successful sudo to ROOT executed.":
        short="W-Aut-Sud"
    if description == "Suspicious URL access.":
        short="W-Acc-Sus"
    if description == "syslog: User authentication failure.":
        short="W-Sys-Fai"
    if description == "User successfully changed UID.":
        short="W-Aut-Uid"
    if description == "Web server 400 error code.":
        short="W-Acc-400"
    if description == "Web server 500 error code (Internal Error).":
        short="W-Acc-500"
    if short is None:
        print('Warning: ' + description)
    return short

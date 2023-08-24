# alert-data-set

This repostiory contains scripts to generate and analyze the [AIT Alert Data Set (AIT-ADS)](https://zenodo.org/record/8263181). The data set contains alerts from the three intrusion detection systems AMiner, Wazuh, and Suricata, applied on the [AIT Log Data Set V2.0 (AIT-LDSv2)](https://zenodo.org/record/5789064). In the following, we will explain how to generate the alert data sets in case that you want to change configurations of detectors. Of course you do not need to generate the data yourself; if you are only interested in analyzing the data and using it for evaluations, download the AIT-ADS from [Zenodo](https://zenodo.org/record/8263181) or proceed to the [Analysis](#analysis) section.

## Generation

### Wazuh and Suricata

To generate the alerts, first make sure that you have a [Wazuh](https://wazuh.com/) installed and set up on your system. Then download one of the scenarios from the [AIT-LDSv2](https://zenodo.org/record/8263181) and unzip it to the location `/home/ubuntu/aitldsv2/<scenario_name>` (if you use any other location, make sure to adapt the path in the python scripts used in the following). Since Wazuh needs to ingest the logs in real-time, we prepared a script that reads out the timestamps of the log events and replays them - this means that generating the alerts takes just as long as the time span of the AIT-LDSv2, which is around 4-6 days per scenario. Create a directory where the logs should be generated into; we use `/var/log/replay/` in the following (if you use any other location, make sure to adapt the path in the python scripts and ossec.conf file). Finally, start the Wazuh client, clone this repository, specify the scenario name in the `replay_logs.py` script, and run the script to replay the log data. The following snippet summarizes these steps for the fox scenario.

```
ubuntu@ubuntu:~$ mkdir aitldsv2
ubuntu@ubuntu:~$ cd aitldsv2/
ubuntu@ubuntu:~/aitldsv2$ wget https://zenodo.org/record/5789064/files/fox.zip
ubuntu@ubuntu:~/aitldsv2$ unzip fox.zip -d fox
ubuntu@ubuntu:~/aitldsv2$ cd ..
ubuntu@ubuntu:~$ git clone https://github.com/ait-aecid/alert-data-set.git
ubuntu@ubuntu:~$ systemctl restart wazuh-agent.service
ubuntu@ubuntu:~$ cd alert-data-set/
ubuntu@ubuntu:~/alert-data-set$ vim replay_logs.py
ubuntu@ubuntu:~/alert-data-set$ python3 replay_logs.py
```

Once the script has finished, collect the alerts from Wazuh Manager. Note that the alerts stored in the elastic database also contain alerts from Suricata. The reason for this is that Suricata was already deployed when running the simulation of the AIT-LDSv2; conveniently, Wazuh collects these alerts and stores them together with the alerts triggered by its own rules in the database. One possibility to copy the alerts from the database to a local file is elasticdump:

```
ubuntu@ubuntu:~$ export NODE_TLS_REJECT_UNAUTHORIZED=0
ubuntu@ubuntu:~$ npx elasticdump --input=https://<url_to_elastic> --output=/home/ubuntu/fox_wazuh.json --type=data --limit=5000
```

### AMiner

Since the `replay_logs.py` script stores all rotated logs in single files and renames them to a common scheme, we utilize these logs for anomaly detection with AMiner. Copy the logs from `/var/log/replay/` to `/home/ubuntu/replay/<scenario_name>/` (if you use any other location, make sure to adapt the paths in the `aminer_config.yml` file). Make sure that you have a running [AMiner](https://github.com/ait-aecid/logdata-anomaly-miner) instance set up on your system. Then specify the paths to the input files as well as the path to the output file containing the anomalies (by default, this is `/tmp/aminer_out.log`) in the `aminer_config.yml` file and run the AMiner. Note that the AMiner is capable of processing the logs forensically and should thus complete within a few minutes.

```
ubuntu@ubuntu:~/alert-data-set$ cp -r /var/log/replay /home/ubuntu/replay/fox
ubuntu@ubuntu:~/alert-data-set$ vim aminer_config.yml
ubuntu@ubuntu:~/alert-data-set$ aminer -C -c aminer_config.yml
```

Proceed in the same way with all other scenarios.

## Analysis

Create a directory in this repository and download the AIT-ADS as follows.

```
ubuntu@ubuntu:~/alert-data-set$ mkdir alerts_raw
ubuntu@ubuntu:~/alert-data-set/alerts_raw$ wget https://zenodo.org/record/8263181/files/ait_ads.zip
ubuntu@ubuntu:~/alert-data-set/alerts_raw$ unzip ait_ads.zip
ubuntu@ubuntu:~/alert-data-set/alerts_raw$ cd ..
```

Then, run the following script to analyze the data. This will (i) apply prioritization and output a (latex-formatted) table for all detectors, and (ii) create csv files for alert occurrences in the `alerts_csv` directory for further analysis.

```
ubuntu@ubuntu:~/alert-data-set$ python3 analyze.py
& network\_scans & service\_scans & wpscan & dirb & webshell & cracking & reverse\_shell & privilege\_escalation & service\_stop & dnsteal & false\_positive\_test & robustness & detection \\ \hline
W-Aut-Ssh2 &   & 8 &   &   &   &   &   &   &   &   &   & 1.0 & 1.0 \\ \hline
W-Err-Fbd2 &   & 5 & 3 & 8 &   &   &   &   &   &   &   & 1.0 & 1.0 \\ \hline
W-All-Mul3 &   & 5 & 8 & 8 &   &   &   &   &   &   &   & 1.0 & 1.0 \\ \hline
W-Acc-Sus &   &   & 6 & 8 &   &   &   &   &   &   &   & 1.0 & 1.0 \\ \hline
...
ubuntu@ubuntu:~/alert-data-set$ head alerts_csv/russellmitchell_alerts.txt
time,name,ip,host,short
1642723347,Wazuh: ClamAV database update,172.19.130.4,mail,W-Sys-Cav
1642723352,Wazuh: ClamAV database update,172.19.130.4,mail,W-Sys-Cav
1642723357,Wazuh: ClamAV database update,172.19.130.4,mail,W-Sys-Cav
1642723362,Wazuh: ClamAV database update,172.19.130.4,mail,W-Sys-Cav
1642723367,Wazuh: ClamAV database update,172.19.130.4,mail,W-Sys-Cav
1642723368,Wazuh: ClamAV database update,172.19.130.4,mail,W-Sys-Cav
1642723432,Wazuh: ClamAV database update,192.168.231.56,davey_mail,W-Sys-Cav
1642724061,Suricata: Alert - ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management,10.143.0.103,internal_share,S-Flw-Apt
1642724061,Wazuh: First time this IDS alert is generated.,10.143.0.103,internal_share,W-All-Ids
```

If you use the AIT-ADS, please cite the following publications:

* Landauer, M., Skopik, F., & Wurzenberger, M.: Introducing a New Alert Data Set for Multi-Step Attack Analysis. Under review.
* Landauer M., Skopik F., Frank M., Hotwagner W., Wurzenberger M., Rauber A. (2023): [Maintainable Log Datasets for Evaluation of Intrusion Detection Systems.](https://ieeexplore.ieee.org/abstract/document/9866880) IEEE Transactions on Dependable and Secure Computing, vol. 20, no. 4, pp. 3466-3482. \[[PDF](https://arxiv.org/pdf/2203.08580.pdf)\]

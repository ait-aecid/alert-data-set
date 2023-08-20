from datetime import datetime
import pytz

phase = {'russellmitchell': {'network_scans': [datetime.strptime("2022-01-24 03:01:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-24 03:56:46", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "service_scans": [datetime.strptime("2022-01-24 03:56:46", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-24 03:57:25", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "dirb": [datetime.strptime("2022-01-24 03:57:25", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-24 03:57:48", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "wpscan": [datetime.strptime("2022-01-24 03:57:48", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-24 03:58:19", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "webshell": [datetime.strptime("2022-01-24 03:58:19", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-24 03:59:22", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "cracking": [datetime.strptime("2022-01-24 03:59:22", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-24 04:36:56", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "reverse_shell": [datetime.strptime("2022-01-24 04:36:56", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-24 04:37:39", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "privilege_escalation": [datetime.strptime("2022-01-24 04:37:39", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-24 04:38:13", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "service_stop": [datetime.strptime("2022-01-24 13:50:38", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-24 13:50:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                                                         "dnsteal": [datetime.strptime("2022-01-24 13:50:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-24 14:50:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                                                         "false_positive_test": [datetime.strptime("2022-01-23 01:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-23 06:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "false_positive_same_day": [datetime.strptime("2022-01-24 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-25 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)]},
		'fox': {             "network_scans": [datetime.strptime("2022-01-18 11:59:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-18 12:17:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "service_scans": [datetime.strptime("2022-01-18 12:17:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-18 12:17:47", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "wpscan": [datetime.strptime("2022-01-18 12:17:47", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-18 12:18:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "dirb": [datetime.strptime("2022-01-18 12:18:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-18 12:38:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "webshell": [datetime.strptime("2022-01-18 12:38:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-18 12:38:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "cracking": [datetime.strptime("2022-01-18 12:38:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-18 13:13:50", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "reverse_shell": [datetime.strptime("2022-01-18 13:13:50", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-18 13:14:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "privilege_escalation": [datetime.strptime("2022-01-18 13:14:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-18 13:14:53", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "service_stop": [datetime.strptime("2022-01-17 09:04:46", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-17 09:04:48", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                                                         "dnsteal": [datetime.strptime("2022-01-17 09:04:48", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-17 10:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                                                         "false_positive_test": [datetime.strptime("2022-01-17 11:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-17 16:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "false_positive_same_day": [datetime.strptime("2022-01-18 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-19 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)]},
		'harrison': {        "network_scans": [datetime.strptime("2022-02-08 07:05:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-08 07:16:19", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "service_scans": [datetime.strptime("2022-02-08 07:16:19", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-08 07:28:36", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "wpscan": [datetime.strptime("2022-02-08 07:28:36", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-08 07:29:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
							 "dirb": [datetime.strptime("2022-02-08 07:29:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-08 07:55:59", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "webshell": [datetime.strptime("2022-02-08 07:55:59", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-08 07:56:37", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "cracking": [datetime.strptime("2022-02-08 07:56:37", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-08 08:35:59", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "reverse_shell": [datetime.strptime("2022-02-08 08:35:59", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-08 08:36:37", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "privilege_escalation": [datetime.strptime("2022-02-08 08:36:37", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-08 08:37:26", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "service_stop": [datetime.strptime("2022-02-08 09:14:59", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-08 09:15:01", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "dnsteal": [datetime.strptime("2022-02-08 09:15:01", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-08 11:15:01", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "false_positive_test": [datetime.strptime("2022-02-07 05:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-07 09:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "false_positive_same_day": [datetime.strptime("2022-02-08 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-09 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)]},
		'santos': {"network_scans": [datetime.strptime("2022-01-17 11:15:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-17 11:21:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "service_scans": [datetime.strptime("2022-01-17 11:21:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-17 11:22:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "dirb": [datetime.strptime("2022-01-17 11:22:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-17 11:22:21", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "wpscan": [datetime.strptime("2022-01-17 11:22:21", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-17 11:22:58", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "webshell": [datetime.strptime("2022-01-17 11:22:58", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-17 11:24:16", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "cracking": [datetime.strptime("2022-01-17 11:24:16", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-17 11:57:35", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "reverse_shell": [datetime.strptime("2022-01-17 11:57:35", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-17 11:58:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "privilege_escalation": [datetime.strptime("2022-01-17 11:58:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-17 11:58:59", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "service_stop": [datetime.strptime("2022-01-16 07:16:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-16 07:16:19", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "dnsteal": [datetime.strptime("2022-01-16 07:16:19", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-16 08:16:19", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "false_positive_test": [datetime.strptime("2022-01-16 10:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-16 15:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "false_positive_same_day": [datetime.strptime("2022-01-17 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-18 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)]},
		'shaw': {"network_scans": [datetime.strptime("2022-01-29 14:37:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-29 14:38:37", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "service_scans": [datetime.strptime("2022-01-29 14:38:37", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-29 14:38:50", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "wpscan": [datetime.strptime("2022-01-29 14:38:50", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-29 14:39:14", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "dirb": [datetime.strptime("2022-01-29 14:39:14", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-29 14:39:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "webshell": [datetime.strptime("2022-01-29 14:39:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-29 14:40:01", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "cracking": [datetime.strptime("2022-01-29 14:40:01", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-29 15:20:10", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "reverse_shell": [datetime.strptime("2022-01-29 15:20:10", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-29 15:20:50", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "privilege_escalation": [datetime.strptime("2022-01-29 15:20:50", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-29 15:21:12", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "service_stop": [datetime.strptime("2022-01-28 21:08:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-28 21:08:02", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "dnsteal": [datetime.strptime("2022-01-28 21:08:02", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-28 22:08:02", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "false_positive_test": [datetime.strptime("2022-01-28 12:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-28 17:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "false_positive_same_day": [datetime.strptime("2022-01-29 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-30 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)]},
		'wardbeck': {"network_scans": [datetime.strptime("2022-01-23 12:10:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-23 12:11:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "service_scans": [datetime.strptime("2022-01-23 12:11:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-23 12:11:27", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "wpscan": [datetime.strptime("2022-01-23 12:11:27", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-23 12:11:49", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "dirb": [datetime.strptime("2022-01-23 12:11:49", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-23 12:12:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "webshell": [datetime.strptime("2022-01-23 12:12:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-23 12:13:45", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "cracking": [datetime.strptime("2022-01-23 12:13:45", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-23 12:54:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "reverse_shell": [datetime.strptime("2022-01-23 12:54:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-23 12:55:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "privilege_escalation": [datetime.strptime("2022-01-23 12:55:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-23 12:55:31", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "service_stop": [datetime.strptime("2022-01-20 22:12:27", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-20 22:12:29", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "dnsteal": [datetime.strptime("2022-01-20 22:12:29", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-20 23:12:29", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "false_positive_test": [datetime.strptime("2022-01-22 10:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-22 15:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "false_positive_same_day": [datetime.strptime("2022-01-23 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-24 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)]},
		'wheeler': {"network_scans": [datetime.strptime("2022-01-30 07:35:13", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-30 07:39:03", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "service_scans": [datetime.strptime("2022-01-30 07:39:03", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-30 07:39:29", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "wpscan": [datetime.strptime("2022-01-30 07:56:04", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-30 07:56:46", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "dirb": [datetime.strptime("2022-01-30 07:39:29", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-30 07:56:04", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "webshell": [datetime.strptime("2022-01-30 07:56:46", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-30 07:57:08", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
        #                     "cracking": [datetime.strptime("2022-01-30 07:57:08", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-30 17:51:12", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "reverse_shell": [datetime.strptime("2022-01-30 17:51:12", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-30 17:51:52", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "privilege_escalation": [datetime.strptime("2022-01-30 17:51:52", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-30 17:52:20", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "service_stop": [datetime.strptime("2022-01-29 05:27:24", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-29 05:27:26", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "dnsteal": [datetime.strptime("2022-01-29 05:27:26", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-29 06:27:26", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "false_positive_test": [datetime.strptime("2022-01-29 07:30:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-29 18:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "false_positive_same_day": [datetime.strptime("2022-01-30 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-01-31 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)]},
		'wilson': {"network_scans": [datetime.strptime("2022-02-07 10:57:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-07 10:59:13", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "service_scans": [datetime.strptime("2022-02-07 10:59:13", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-07 10:59:44", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "wpscan": [datetime.strptime("2022-02-07 11:19:53", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-07 11:20:27", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "dirb": [datetime.strptime("2022-02-07 10:59:44", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-07 11:19:53", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "webshell": [datetime.strptime("2022-02-07 11:20:27", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-07 11:20:39", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "cracking": [datetime.strptime("2022-02-07 11:20:39", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-07 11:47:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "reverse_shell": [datetime.strptime("2022-02-07 11:47:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-07 11:48:18", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "privilege_escalation": [datetime.strptime("2022-02-07 11:48:18", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-07 11:48:53", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "service_stop": [datetime.strptime("2022-02-06 10:47:15", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-06 10:47:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "dnsteal": [datetime.strptime("2022-02-06 10:47:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-06 11:47:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "false_positive_test": [datetime.strptime("2022-02-06 13:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-06 18:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)],
                             "false_positive_same_day": [datetime.strptime("2022-02-07 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc), datetime.strptime("2022-02-08 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc)]}
	}

def get_duration(scenario, p):
    if p == "false_positive_same_day":
        print("Please use the get_attack_free_duration to get duration of non-attack time")
        return None
    return (phase[scenario][p][1] - phase[scenario][p][0]).total_seconds()

#def get_attack_free_duration(scenario):
#    key_phase = "false_positive_same_day"
#    total = (phase[scenario][key_phase][1] - phase[scenario][key_phase][0]).total_seconds()
#    for p in phase[scenario]:
#        if p == key_phase:
#            continue
#        total -= (phase[scenario][p][1] - phase[scenario][p][0]).total_seconds()
#    return total

def get_phase(scenario, time):
    p = "false_positive_other_day"
    for test_phase, interval in phase[scenario].items():
        if time >= interval[0].timestamp() and time < interval[1].timestamp():
            return test_phase
    return p

def get_phase_old(scenario, time):
    phase = "false_positive_other_day"
    if scenario == "russellmitchell":
        if time >= datetime.strptime("2022-01-24 03:01:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-24 03:56:46", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "network_scans"
        elif time >= datetime.strptime("2022-01-24 03:56:46", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-24 03:57:25", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "service_scans"
        elif time >= datetime.strptime("2022-01-24 03:57:25", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-24 03:57:48", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dirb"
        elif time >= datetime.strptime("2022-01-24 03:57:48", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-24 03:58:19", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "wpscan"
        elif time >= datetime.strptime("2022-01-24 03:58:19", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-24 03:59:22", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "webshell"
        elif time >= datetime.strptime("2022-01-24 03:59:22", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-24 04:36:56", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "cracking"
        elif time >= datetime.strptime("2022-01-24 04:36:56", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-24 04:37:39", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "reverse_shell"
        elif time >= datetime.strptime("2022-01-24 04:37:39", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-24 04:38:13", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "privilege_escalation"
        elif time >= datetime.strptime("2022-01-24 13:50:38", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-24 13:50:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dnsteal"
        elif time >= datetime.strptime("2022-01-24 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-25 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "false_positive_same_day"
    elif scenario == "fox":
        if time >= datetime.strptime("2022-01-18 11:59:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-18 12:17:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "network_scans"
        elif time >= datetime.strptime("2022-01-18 12:17:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-18 12:17:47", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "service_scans"
        elif time >= datetime.strptime("2022-01-18 12:17:47", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-18 12:18:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "wpscan"
        elif time >= datetime.strptime("2022-01-18 12:18:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-18 12:38:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dirb"
        elif time >= datetime.strptime("2022-01-18 12:38:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-18 12:38:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "webshell"
        elif time >= datetime.strptime("2022-01-18 12:38:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-18 13:13:50", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "cracking"
        elif time >= datetime.strptime("2022-01-18 13:13:50", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-18 13:14:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "reverse_shell"
        elif time >= datetime.strptime("2022-01-18 13:14:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-18 13:14:53", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "privilege_escalation"
        elif time >= datetime.strptime("2022-01-17 09:04:46", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-17 09:04:48", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dnsteal"
        elif time >= datetime.strptime("2022-01-18 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-19 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "false_positive_same_day"
    elif scenario == "harrison":
        if time >= datetime.strptime("2022-02-08 07:05:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-08 07:16:19", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "network_scans"
        elif time >= datetime.strptime("2022-02-08 07:16:19", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-08 07:28:36", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "service_scans"
        elif time >= datetime.strptime("2022-02-08 07:28:36", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-08 07:29:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "wpscan"
        elif time >= datetime.strptime("2022-02-08 07:29:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-08 07:55:59", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dirb"
        elif time >= datetime.strptime("2022-02-08 07:55:59", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-08 07:56:37", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "webshell"
        elif time >= datetime.strptime("2022-02-08 07:56:37", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-08 08:35:59", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "cracking"
        elif time >= datetime.strptime("2022-02-08 08:35:59", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-08 08:36:37", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "reverse_shell"
        elif time >= datetime.strptime("2022-02-08 08:36:37", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-08 08:37:26", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "privilege_escalation"
        elif time >= datetime.strptime("2022-02-08 09:14:59", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-08 09:15:01", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dnsteal"
        elif time >= datetime.strptime("2022-02-08 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-09 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "false_positive_same_day"
    elif scenario == "santos":
        if time >= datetime.strptime("2022-01-17 11:15:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-17 11:21:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "network_scans"
        elif time >= datetime.strptime("2022-01-17 11:21:30", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-17 11:22:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "service_scans"
        elif time >= datetime.strptime("2022-01-17 11:22:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-17 11:22:21", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dirb"
        elif time >= datetime.strptime("2022-01-17 11:22:21", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-17 11:22:58", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "wpscan"
        elif time >= datetime.strptime("2022-01-17 11:22:58", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-17 11:24:16", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "webshell"
        elif time >= datetime.strptime("2022-01-17 11:24:16", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-17 11:57:35", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "cracking"
        elif time >= datetime.strptime("2022-01-17 11:57:35", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-17 11:58:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "reverse_shell"
        elif time >= datetime.strptime("2022-01-17 11:58:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-17 11:58:59", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "privilege_escalation"
        elif time >= datetime.strptime("2022-01-16 07:16:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-16 07:16:19", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dnsteal"
        elif time >= datetime.strptime("2022-01-17 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-18 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "false_positive_same_day"
    elif scenario == "shaw":
        if time >= datetime.strptime("2022-01-29 14:37:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-29 14:38:37", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "network_scans"
        elif time >= datetime.strptime("2022-01-29 14:38:37", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-29 14:38:50", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "service_scans"
        elif time >= datetime.strptime("2022-01-29 14:38:50", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-29 14:39:14", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "wpscan"
        elif time >= datetime.strptime("2022-01-29 14:39:14", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-29 14:39:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dirb"
        elif time >= datetime.strptime("2022-01-29 14:39:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-29 14:40:01", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "webshell"
        elif time >= datetime.strptime("2022-01-29 14:40:01", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-29 15:20:10", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "cracking"
        elif time >= datetime.strptime("2022-01-29 15:20:10", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-29 15:20:50", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "reverse_shell"
        elif time >= datetime.strptime("2022-01-29 15:20:50", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-29 15:21:12", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "privilege_escalation"
        elif time >= datetime.strptime("2022-01-28 21:08:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-28 21:08:02", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dnsteal"
        elif time >= datetime.strptime("2022-01-29 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-30 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "false_positive_same_day"
    elif scenario == "wardbeck":
        if time >= datetime.strptime("2022-01-23 12:10:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-23 12:11:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "network_scans"
        elif time >= datetime.strptime("2022-01-23 12:11:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-23 12:11:27", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "service_scans"
        elif time >= datetime.strptime("2022-01-23 12:11:27", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-23 12:11:49", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "wpscan"
        elif time >= datetime.strptime("2022-01-23 12:11:49", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-23 12:12:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dirb"
        elif time >= datetime.strptime("2022-01-23 12:12:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-23 12:13:45", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "webshell"
        elif time >= datetime.strptime("2022-01-23 12:13:45", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-23 12:54:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "cracking"
        elif time >= datetime.strptime("2022-01-23 12:54:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-23 12:55:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "reverse_shell"
        elif time >= datetime.strptime("2022-01-23 12:55:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-23 12:55:31", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "privilege_escalation"
        elif time >= datetime.strptime("2022-01-20 22:12:27", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-20 22:12:29", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dnsteal"
        elif time >= datetime.strptime("2022-01-23 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-24 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "false_positive_same_day"
    elif scenario == "wheeler":
        if time >= datetime.strptime("2022-01-30 07:35:13", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-30 07:39:03", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "network_scans"
        elif time >= datetime.strptime("2022-01-30 07:39:03", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-30 07:39:29", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "service_scans"
        elif time >= datetime.strptime("2022-01-30 07:56:04", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-30 07:56:46", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "wpscan"
        elif time >= datetime.strptime("2022-01-30 07:39:29", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-30 07:56:04", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dirb"
        elif time >= datetime.strptime("2022-01-30 07:56:46", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-30 07:57:08", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "webshell"
        #elif time >= datetime.strptime("2022-01-30 07:57:08", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-30 17:51:12", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
        #    phase = "cracking"
        elif time >= datetime.strptime("2022-01-30 17:51:12", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-30 17:51:52", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "reverse_shell"
        elif time >= datetime.strptime("2022-01-30 17:51:52", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-30 17:52:20", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "privilege_escalation"
        elif time >= datetime.strptime("2022-01-29 05:27:24", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-29 05:27:26", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dnsteal"
        elif time >= datetime.strptime("2022-01-30 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-01-31 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "false_positive_same_day"
    elif scenario == "wilson":
        if time >= datetime.strptime("2022-02-07 10:57:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-07 10:59:13", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "network_scans"
        elif time >= datetime.strptime("2022-02-07 10:59:13", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-07 10:59:44", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "service_scans"
        elif time >= datetime.strptime("2022-02-07 11:19:53", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-07 11:20:27", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "wpscan"
        elif time >= datetime.strptime("2022-02-07 10:59:44", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-07 11:19:53", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dirb"
        elif time >= datetime.strptime("2022-02-07 11:20:27", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-07 11:20:39", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "webshell"
        elif time >= datetime.strptime("2022-02-07 11:20:39", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-07 11:47:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "cracking"
        elif time >= datetime.strptime("2022-02-07 11:47:40", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-07 11:48:18", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "reverse_shell"
        elif time >= datetime.strptime("2022-02-07 11:48:18", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-07 11:48:53", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "privilege_escalation"
        elif time >= datetime.strptime("2022-02-06 10:47:15", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-06 10:47:17", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "dnsteal"
        elif time >= datetime.strptime("2022-02-07 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp() and time < datetime.strptime("2022-02-08 00:00:00", "%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp():
            phase = "false_positive_same_day"
    return phase

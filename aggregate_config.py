# Specifies the input data, where it is possible to use multiple alert sources (IDS) running on the same system in parallel, and arbitrary many systems, e.g.,
# files = [[system_A_ids_1, system_A_ids_2], [system_B_ids_1, system_B_ids_2, system_B_ids_3, ...], ...]
# For a single file, just use files = [['path_to_file']]
files = [['../alerts_filtered/fox_aminer.json', '../alerts_filtered/fox_wazuh.json'],
        ['../alerts_filtered/harrison_aminer.json', '../alerts_filtered/harrison_wazuh.json'],
        ['../alerts_filtered/russellmitchell_aminer.json', '../alerts_filtered/russellmitchell_wazuh.json'],
        ['../alerts_filtered/santos_aminer.json', '../alerts_filtered/santos_wazuh.json'],
        ['../alerts_filtered/shaw_aminer.json', '../alerts_filtered/shaw_wazuh.json'],
        ['../alerts_filtered/wardbeck_aminer.json', '../alerts_filtered/wardbeck_wazuh.json'],
        ['../alerts_filtered/wheeler_aminer.json', '../alerts_filtered/wheeler_wazuh.json'],
        ['../alerts_filtered/wilson_aminer.json', '../alerts_filtered/wilson_wazuh.json'],
        ]

input_type = None # Supports 'aminer' or 'ossec'. If None, automatically selects correct parser based on input file directory.
deltas = [2] # Delta time intervals for group formation in seconds.
threshold = 0.55 # Minimum group similarity threshold for incremental clustering [0, 1].
min_alert_match_similarity = 0.5 # Minimum alert similarity threshold for group matching [0,1]. Set to None to use same value as threshold.
max_val_limit = 5 # Maximum number of values in merge lists before they are replaced by wildcards [0, inf].
min_key_occurrence = 0.1 # Minimum relative occurrence frequency of attributes to be included in merged alerts [0, 1].
min_val_occurrence = 0.1 # Minimum relative occurrence frequency of attribute values to be included in attributes of merged alerts [0, 1].
alignment_weight = 0.1 # Influence of alignment on group similarity [0, 1].
max_groups_per_meta_alert = 25 # Maximum queue size [1, inf]. Set to None for unlimited queue size.
queue_strategy = 'logarithmic' # Queue storage strategy, supported strategies are 'linear' and 'logarithmic'.
w = {'timestamp': 0, 'Timestamp': 0, 'timestamps': 0, 'Timestamps': 0, 'DetectionTimestamp': 0, '@timestamp': 0} # Attribute weights used in alert similarity computation. It is recommended to set the weights of timestamps to 0.
output_dir = 'data/out/aggregate/meta_alerts.txt' # Directory where meta-alerts are stored.
output_alerts = False # Specifies whether alerts are printed to file.
output_alerts_dir = 'data/out/aggregate/alerts.txt' # Directory where alerts from input files are stored. 

# standard library

# 3rd party libraries

# project libraries

class Terms:
  api_to_new = {
    'id': 'id',
    'dpistate': 'intrusion_prevention_state',
    'overallintegritymonitoringstatus': 'overall_integrity_monitoring_status',
    'cloudobjecttype': 'cloud_type',
    'overalllastupdaterequired': 'overall_last_update_required',
    'loginspectionruleids': 'log_inspection_rule_ids',
    'statefulconfigurationid': 'stateful_configuration_id',
    'integrityruleids': 'integrity_monitoring_rule_ids',
    'tbuid': 'tbuid',
    'componentversions': 'component_version',
    'externalid': 'external_id',
    'overalllastsuccessfulupdate': 'overall_last_successful_update',
    'parentgroupid': 'parent_group_id',
    'dpiruleids': 'intrusion_prevention_rule_ids',
    'overallantimalwarestatus': 'overall_anti_malware_status',
    'lastantimalwaremanualscan': 'last_anti_malware_manual_scan',
    'overalldpistatus': 'overall_intrusion_prevention_status',
    'hostlight': 'computer_status_light',
    'antimalwarespywarepatternversion': 'anti_malware_spyware_pattern_version',
    'antimalwareclassicpatternversion': 'anti_malware_classic_pattern_version',
    'antimalwarescheduledid': 'anti_malware_scheduled_id',
    'cloudobjectimageid': 'cloud_image_id',
    'antimalwarerealtimeinherit': 'anti_malware_real_time_inherit',
    'antimalwareintellitrapversion': 'anti_malware_intellitrap_version',
    'applicationtypeids': 'application_type_ids',
    'componentnames': 'component_names',
    'antimalwarerealtimescheduleid': 'anti_malware_real_time_schedule_id',
    'overalllastrecommendationscan': 'overall_last_recommendation_scan',
    'overalllastsuccessfulcommunication': 'overall_last_successful_communication',
    'lastipused': 'last_ip_used',
    'integrityruleids': 'integrity_monitoring_rule_ids',
    'recommendationstate': 'recommedation_state',
    'lastantimalwareevent': 'last_anti_malware_event',
    'antimalwaremanualinherit': 'anti_malware_manual_inherit',
    'lastanitmalwarescheduledscan': 'last_anti_malware_scheduled_scan',
    'overallfirewallstatus': 'overall_firewall_status',
    'cloudobjectinstanceid': 'cloud_instance_id',
    'antimalwaremanualid': 'anti_malware_manual_id',
    'lastwebreputationevent': 'last_content_filtering_event',
    'antimalwareintellitrapexceptionversion': 'anti_malware_intellitrap_exception_version',
    'overallloginspectionstatus': 'overall_log_inspection_status',
    'componentklasses': 'component_classes',
    'componenttypes': 'component_types',
    'antimalwarescheduledinherit': 'anti_malware_scheduled_inherit',
    'antimalwarerealtimeid': 'anti_malware_real_time_id',
    'virtualuuid': 'virtual_uuid',
    'hostinterfaces': 'computer_interfaces',
    'parentsecurityprofileid': 'parent_policy_id',
    'cloudobjectsecuritygroupids': 'cloud_security_group_ids',
    'overallversion': 'overall_version',
    'cloudobjectinternaluniqueid': 'cloud_internal_unique_id',
    'hostgroupid': 'computer_group_id',
    'lastintegritymonitoringevent': 'last_integrity_monitoring_event',
    'integritystate': 'integrity_monitoring_state',
    'hostgroupname': 'computer_group_name',
    'antimalwarestate': 'anti_malware_state',
    'antimalwareengineversion': 'anti_malware_engine_version',
    'scheduleid': 'schedule_id',
    'securityprofilename': 'policy_name',
    'displayname': 'display_name',
    'lastloginspectionevent': 'last_log_inspection_event',
    'lastfirewallevent': 'last_firewall_event',
    'firewallstate': 'firewall_state',
    'virtualname': 'virtual_name',
    'loginspectionruleids': 'log_inspection_rule_ids',
    'loginspectionstate': 'log_inspection_state',
    'hosttype': 'computer_type',
    'antimalwaresmartscanpatternversion': 'anti_malware_smartscan_pattern_version',
    'lastdpievent': 'last_intrusion_prevention_event',
    'securityprofileid': 'policy_id',
    'overallwebreputationstatus': 'overall_content_filtering_status',
    'firewallruleids': 'firewall_rule_ids',
    'overallstatus': 'overall_status',
    'firewallruleids': 'firewall_rule_ids',
    'dpiruleretrieveall': 'intrusion_prevention_rule_retrieve_all',
    'firewallruleretrieveall': 'firewall_rule_retrieve_all',
    'integrityruleretrieveall': 'integrity_monitoring_rule_retrieve_all',
    'loginspectionruleretrieveall': 'log_inspection_rule_retrieve_all',
    'applicationtyperetrieveall': 'application_type_retrieve_all',
    'cloudaccountid': 'cloud_account_id',
    'realtimesynchronization': 'real_time_synchronization',
    'cloudregion': 'cloud_region',
    'cloudtype': 'cloud_type',
    'applicationtypeid': 'application_type_id',
    'authoritative': 'authoritative',
    'cvenumbers': 'cve_numbers',
    'cvssscore': 'cvss_score',
    'detectonly': 'detect_only',
    'disableevent': 'disable_event',
    'eventonpacketdrop': 'event_on_packet_drop',
    'eventonpacketmodify': 'event_on_packet_modify',
    'identifier': 'identifier',
    'ignorerecommendations': 'ignore_recommendations',
    'includepacketdata': 'include_packet_data',
    'issued': 'issued',
    'manager': 'manager',
    'msnumbers': 'ms_numbers',
    'name': 'name',
    'patternaction': 'pattern_action',
    'patterncasesensitive': 'pattern_case_sensitive',
    'patternend': 'pattern_end',
    'patternif': 'pattern_if',
    'patternpatterns': 'pattern_patterns',
    'patternstart': 'pattern_start',
    'policies': 'policies',
    'priority': 'priority',
    'raisealert': 'raise_alert',
    'rulexml': 'rule_xml',
    'rule_type': 'rule_type',
    'schedule_id': 'schedule_id',
    'severity': 'severity',
    'signatureaction': 'signature_action',
    'signaturecasesensitive': 'signature_casesensitive',
    'signaturesignature': 'signature_signature',
    'templatetype': 'template_type',
    'action': 'action',
    'anyflags': 'any_flags',
    'destinationip': 'destination_ip',
    'destinationiplistid': 'destination_ip_list_id',
    'destinationipmask': 'destination_ip_mask',
    'destinationipnot': 'destination_ip_not',
    'destinationiprangefrom': 'destination_ip_range_from',
    'destinationiprangeto': 'destination_ip_range_to',
    'destinationiptype': 'destination_ip_type',
    'destinationmac': 'destination_mac',
    'destinationmaclistid': 'destination_mac_list_id',
    'destinationmacnot': 'destination_mac_not',
    'destinationmactype': 'destination_mac_type',
    'destinationportlistid': 'destination_port_list_id',
    'destinationportnot': 'destination_port_not',
    'destinationporttype': 'destination_port_type',
    'destinationports': 'destination_ports',
    'destinationsingleip': 'destination_single_ip',
    'disabledlog': 'disabled_log',
    'framenot': 'frame_not',
    'framenumber': 'frame_number',
    'frametype': 'frame_type',
    'icmpcode': 'icmp_code',
    'icmpnot': 'icmp_not',
    'icmptype': 'icmp_type',
    'packetdirection': 'packet_direction',
    'policies': 'policies',
    'priority': 'priority',
    'protocolnot': 'protocol_not',
    'protocolnumber': 'protocol_number',
    'protocoltype': 'protocol_type',
    'raisealert': 'raise_alert',
    'rule_type': 'rule_type',
    'schedule_id': 'schedule_id',
    'sourceip': 'source_ip',
    'sourceiplistid': 'source_ip_list_id',
    'sourceipmask': 'source_ip_mask',
    'sourceipnot': 'source_ip_not',
    'sourceiprangefrom': 'source_ip_range_from',
    'sourceiprangeto': 'source_ip_range_to',
    'sourceiptype': 'source_ip_type',
    'sourcemac': 'source_mac',
    'sourcemaclistid': 'source_mac_list_id',
    'sourcemacnot': 'source_mac_not',
    'sourcemactype': 'source_mac_type',
    'sourceportlistid': 'source_port_list_id',
    'sourceportnot': 'source_port_not',
    'sourceporttype': 'source_port_type',
    'sourceports': 'source_ports',
    'sourcesingleip': 'source_single_ip',
    'tcpflagack': 'tcp_flag_ack',
    'tcpflagfin': 'tcp_flag_fin',
    'tcpflagpsh': 'tcp_flag_psh',
    'tcpflagrst': 'tcp_flag_rst',
    'tcpflagsyn': 'tcp_flag_syn',
    'tcpflagurg': 'tcp_flag_urg',
    'tcpnot': 'tcp_not',
    'alertminseverity': 'alert_min_severity',
    'authoritative': 'authoritative',
    'content': 'content',
    'files': 'files',
    'identifier': 'identifier',
    'ignorerecommendations': 'ignore_recommendations',
    'issued': 'issued',
    'minagentversion': 'min_agent_version',
    'minmanagerversion': 'min_manager_version',
    'policies': 'policies',
    'raisealert ': 'raise_alert ', 
    'allowonchange': 'allow_on_change',
    'protocolicmp': 'protocol_icmp',
    'protocolportbased': 'protocol_port_based',
    'protocoltype': 'protocol_type',
    }

  @classmethod
  def get_reverse(self, new_term):
    result = new_term
    for api, new in Terms.api_to_new.items():
      if new == new_term:
        result = api

    return result

  @classmethod
  def get(self, api_term):
    """
    Return the translation of the specified API term
    """
    if Terms.api_to_new.has_key(api_term.lower()):
      return self.api_to_new[api_term.lower()]
    else:
      return api_term
class SuricataParser {
  static parse(rawLog, organizationId, assetId, logSourceId) {
    if (!rawLog || !rawLog.event_type) return null;
    
    const severityMap = {
      1: 'high',
      2: 'medium',
      3: 'low',
    };

    let severity = 'info';
    let message = `Suricata ${rawLog.event_type} event from ${rawLog.src_ip || 'unknown'}`;
    let eventCategory = 'network';
    
    if (rawLog.event_type === 'alert' && rawLog.alert) {
      severity = severityMap[rawLog.alert.severity] || 'info';
      message = `Suricata Alert: ${rawLog.alert.signature}`;
      eventCategory = 'network';
    } else if (rawLog.event_type === 'dns') {
      message = `Suricata DNS Query: ${rawLog.dns?.rrname || 'unknown'}`;
    } else if (rawLog.event_type === 'http') {
      message = `Suricata HTTP ${rawLog.http?.http_method} ${rawLog.http?.hostname}`;
    } else if (rawLog.event_type === 'tls') {
      message = `Suricata TLS Connection: ${rawLog.tls?.sni || 'unknown'}`;
    }

    const log = {
      organization: organizationId,
      asset: assetId,
      logSource: logSourceId,
      sourceType: 'suricata',
      eventCategory: eventCategory,
      eventType: rawLog.event_type,
      severity: severity,
      sourceIP: rawLog.src_ip,
      destinationIP: rawLog.dest_ip,
      destinationPort: rawLog.dest_port,
      protocol: rawLog.proto || 'TCP',
      message: message,
      rawLog: rawLog,
      normalizedData: {
        suricata: rawLog
      },
      eventTime: rawLog.timestamp ? new Date(rawLog.timestamp) : new Date(),
      isTestEvent: rawLog.isTestEvent || false,
      securityTestId: rawLog.securityTestId || null
    };
    
    return log;
  }
}

module.exports = SuricataParser;

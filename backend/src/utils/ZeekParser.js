class ZeekParser {
  static parse(rawLog, logType, organizationId, assetId, logSourceId) {
    if (!rawLog) return null;
    
    const ts = rawLog.ts;
    const date = ts ? (typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts)) : new Date();

    const orig_h = rawLog['id.orig_h'] || rawLog.id?.orig_h;
    const resp_h = rawLog['id.resp_h'] || rawLog.id?.resp_h;
    const resp_p = rawLog['id.resp_p'] || rawLog.id?.resp_p;
    
    let message = `Zeek ${logType || 'unknown'} event`;
    let severity = 'info';

    if (logType === 'conn') {
      message = `Zeek Connection from ${orig_h} to ${resp_h}:${resp_p}`;
    } else if (logType === 'dns') {
      message = `Zeek DNS Query: ${rawLog.query || 'unknown'}`;
    } else if (logType === 'http') {
      message = `Zeek HTTP ${rawLog.method} ${rawLog.host}`;
    } else if (logType === 'ssl') {
      message = `Zeek SSL/TLS Connection: ${rawLog.server_name || 'unknown'}`;
    }

    const log = {
      organization: organizationId,
      asset: assetId,
      logSource: logSourceId,
      sourceType: 'zeek',
      eventCategory: 'network',
      eventType: logType || 'unknown',
      severity: severity,
      sourceIP: orig_h,
      destinationIP: resp_h,
      destinationPort: resp_p,
      protocol: rawLog.proto || rawLog.service || 'TCP',
      message: message,
      rawLog: rawLog,
      normalizedData: {
        zeek: rawLog
      },
      eventTime: date,
      isTestEvent: rawLog.isTestEvent || false,
      securityTestId: rawLog.securityTestId || null
    };
    
    return log;
  }
}

module.exports = ZeekParser;

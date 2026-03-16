# Analysis Guides

Learn how to effectively analyze network traffic using mcpcap's specialized capabilities.

## DNS Analysis Fundamentals

### Understanding DNS Packet Structure

DNS packets contain several key components that mcpcap analyzes:

- **Header**: Contains flags, response codes, and packet metadata
- **Questions**: What domain names are being queried
- **Answers**: The responses to DNS queries
- **Authority**: Authoritative name server information
- **Additional**: Extra resource records

### Key Metrics to Monitor

**Query/Response Ratio**
- Normal: ~1:1 ratio (each query gets a response)
- Suspicious: Many queries without responses (DNS tunneling)
- Problem: High query count with NXDOMAIN responses

**Unique Domains**
- Normal: Varied domain names from typical browsing
- Suspicious: Random-looking domain names (DGA malware)
- Problem: Queries to non-existent domains

**Query Frequency**
- Normal: Sporadic queries matching user activity
- Suspicious: Regular intervals (beaconing behavior)
- Problem: Excessive queries indicating DNS recursion loops

## Security Analysis

### Identifying Malicious Activity

**Domain Generation Algorithm (DGA) Detection**

Look for domains with these characteristics:
- Long random-looking strings
- Excessive consonants or numbers
- Unusual TLD combinations
- High query frequency to non-existent domains

```json
{
  "suspicious_patterns": [
    "a8f3k2l9m.com",
    "xj9pk2lmn4.biz",
    "random123abc.tk"
  ]
}
```

**DNS Tunneling Indicators**

- Unusually long DNS queries (>100 characters)
- High volume of TXT record queries
- Encoded data in subdomain names
- Regular query intervals

**Command & Control (C2) Communication**

- Periodic DNS queries to specific domains
- Consistent query timing patterns
- Queries to recently registered domains
- Non-standard DNS record types

### Security Analysis Workflow

1. **Initial Assessment**
   ```
   Use analyze_dns_packets() to get overview statistics
   Look for unusual domain counts or query patterns
   ```

2. **Pattern Recognition**
   ```
   Filter for domains with suspicious characteristics
   Analyze query timing and frequency
   Check for encoded data in domain names
   ```

3. **Threat Classification**
   ```
   Compare domains against threat intelligence
   Identify potential malware families
   Assess impact and scope
   ```

4. **Evidence Collection**
   ```
   Document all suspicious queries with timestamps
   Extract communication patterns
   Prepare indicators of compromise (IOCs)
   ```

## Network Troubleshooting

### DNS Performance Issues

**High Latency Symptoms**
- Long delays between queries and responses
- Timeout errors and retransmissions
- User complaints about slow web browsing

**Diagnostic Steps**
1. Measure query response times
2. Identify slow DNS servers
3. Check for network path issues
4. Analyze query distribution

**Common Causes**
- Overloaded DNS servers
- Network congestion
- Misconfigured DNS forwarding
- Geographic distance to DNS servers

### Resolution Failures

**NXDOMAIN Analysis**
- Track domains that don't exist
- Identify typos or misconfigured applications
- Detect DNS poisoning attempts

**Timeout Investigation**
- Find queries without responses
- Identify unreachable DNS servers
- Trace network connectivity issues

### Troubleshooting Workflow

1. **Baseline Establishment**
   ```
   Analyze normal DNS traffic patterns
   Document typical response times
   Identify peak usage periods
   ```

2. **Problem Identification**
   ```
   Compare current traffic to baseline
   Identify deviations in timing or patterns
   Locate specific failure points
   ```

3. **Root Cause Analysis**
   ```
   Trace queries from client to server
   Check for intermediate failures
   Analyze server response patterns
   ```

4. **Solution Implementation**
   ```
   Address identified bottlenecks
   Optimize DNS server configuration
   Implement caching strategies
   ```

## Forensic Investigation

### Timeline Analysis

**Chronological Reconstruction**
- Order all DNS events by timestamp
- Correlate queries with known incident times
- Identify patterns in timing and frequency

**Event Correlation**
- Match DNS queries to system events
- Connect domain lookups to file executions
- Link network activity to user actions

### Evidence Collection

**Chain of Custody**
- Document PCAP file sources and timestamps
- Preserve original capture integrity
- Maintain detailed analysis logs

**Data Extraction**
- Export suspicious queries with full metadata
- Document response codes and timing
- Preserve packet-level details for court proceedings

### Attribution Analysis

**Source Identification**
- Map IP addresses to systems or users
- Analyze query patterns for behavioral signatures
- Correlate with other network evidence

**Impact Assessment**
- Determine scope of DNS-based compromise
- Identify potential data exfiltration
- Assess ongoing security risks

### Forensic Workflow

1. **Evidence Preservation**
   ```
   Create forensic copies of PCAP files
   Document analysis environment
   Maintain chain of custody logs
   ```

2. **Timeline Construction**
   ```
   Extract all DNS events with timestamps
   Correlate with incident indicators
   Build comprehensive activity timeline
   ```

3. **Pattern Analysis**
   ```
   Identify recurring DNS queries
   Map communication patterns
   Analyze behavioral signatures
   ```

4. **Report Generation**
   ```
   Document findings with timestamps
   Include technical details and evidence
   Prepare court-ready documentation
   ```

## Advanced Techniques

### Statistical Analysis

**Frequency Analysis**
- Query volume over time
- Domain popularity rankings
- Response code distributions

**Anomaly Detection**
- Identify outliers in query patterns
- Detect unusual domain structures
- Flag abnormal response behaviors

### Data Correlation

**Multi-source Analysis**
- Combine DNS data with other logs
- Correlate with threat intelligence feeds
- Cross-reference with known indicators

**Behavioral Baselines**
- Establish normal DNS patterns
- Create user/system profiles
- Detect deviations from baseline

## Best Practices

### Data Collection

- Capture complete DNS conversations (queries + responses)
- Include sufficient time windows for pattern analysis
- Maintain high-resolution timestamps
- Preserve all DNS record types

### Analysis Approach

- Start with overview statistics before diving deep
- Use multiple analysis techniques for validation
- Document methodology and findings
- Maintain objectivity in threat assessment

### Tool Usage

- Leverage mcpcap's specialized prompts for guidance
- Combine automated analysis with manual review
- Use reference resources for DNS technical details
- Validate findings with additional tools when possible

### Reporting

- Include both technical details and executive summaries
- Provide actionable recommendations
- Document confidence levels in findings
- Maintain professional presentation standards

## DHCP Analysis Fundamentals

### Understanding DHCP Packet Structure

DHCP packets contain several key components:

- **Header**: Message type, transaction ID, flags
- **Client/Server Addresses**: IP address assignments
- **Options**: Network configuration parameters
- **Message Types**: DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE

### Key Metrics to Monitor

**DHCP Transaction Flow**
- Normal: Complete 4-way handshake (DISCOVER→OFFER→REQUEST→ACK)
- Problem: Incomplete transactions or excessive retries
- Security: Unexpected message types or timing

**IP Address Management**
- Normal: Organized lease allocation and renewal
- Problem: Address pool exhaustion or conflicts
- Security: Unauthorized DHCP servers or spoofing

### Security Indicators

**Rogue DHCP Servers**
- Multiple DHCP servers responding
- Unexpected server IP addresses
- Suspicious network configuration options

**DHCP Attacks**
- DHCP starvation (excessive DISCOVER requests)
- Malicious DHCP options (DNS poisoning)
- MAC address spoofing patterns

## ICMP Analysis Fundamentals

### Understanding ICMP Packet Structure

ICMP packets provide network diagnostics:

- **Type/Code**: Message type and sub-type
- **Echo Request/Reply**: Ping functionality
- **Error Messages**: Network unreachable, TTL exceeded
- **Timestamp**: Round-trip time analysis

### Key Metrics to Monitor

**Ping Analysis**
- Normal: Regular echo request/reply pairs
- Problem: High packet loss or excessive latency
- Security: ICMP tunneling or covert channels

**Network Diagnostics**
- Normal: Occasional error messages
- Problem: Excessive unreachable messages
- Security: Network reconnaissance patterns

### Security Indicators

**ICMP-based Attacks**
- ICMP flood attacks
- ICMP tunneling for data exfiltration
- Network reconnaissance and scanning
- Covert channel communication

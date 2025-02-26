# Black9


## WatchGuard

```xml
  <!-- Normal denied traffic -->
  <rule id="150062" level="5">
    <if_sid>150000</if_sid>
    <id>3000-0148</id>
    <action type="pcre2">[Dd]eny</action>
        <match type="pcre2" negate="yes">0.0.0.0\s0.0.0.0\s</match>
    <description>Watchguard: firewall: $(action) $(src) $(dst) packetlen=$(packetlen) $(protocol) iphlen=$(iphlen) ttl=$(ttl) from $(srcip):$(srcport) to $(dstip):$(dstport) - $(reason)</description>
    <group>packet_filter,packet_filter_deny</group>
  </rule>
```


```xml
  <!-- Multiple denied generic traffic -->
  <rule id="150067" level="10" frequency="5" timeframe="300">
    <if_matched_group>packet_filter_deny</if_matched_group>
    <same_srcip />
    <description>Watchguard: firewall: Multiple denied traffic from same source $(srcip)</description>
    <group>firewall,access_denied,pci_dss_10.2.4,pci_dss_11.4,gpg13_4.12,gdpr_IV_35.7.d,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

```


```xml
  <!-- Hostile traffic -->
  <rule id="150069" level="9">
    <if_sid>150000</if_sid>
    <id>3000-0173</id>
    <description>Watchguard: firewall: Hostile traffic $(action) $(src) $(dst) packetlen=$(packetlen) $(protocol) iphlen=$(iphlen) ttl=$(ttl) from $(srcip):$(srcport) to $(dstip):$(dstport) - $(reason)</description>
    <group>firewall</group>
  </rule>

  <!-- Multiple hostile traffic -->
  <rule id="150070" level="13" frequency="10" timeframe="240" ignore="90">
    <if_matched_sid>150069</if_matched_sid>
    <same_srcip />
    <description>Watchguard: firewall: Multiple hostile traffic from same source</description>
    <group>firewall,access_denied,pci_dss_10.2.4,pci_dss_11.4,gpg13_4.12,gdpr_IV_35.7.d,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
```



```xml
  <!-- ICMP hidden tunnel detection when too much packets are larger than standard ICMP packet size

Generic ping max packet size calculation
PING = 56 + 40 + 8 = 104
Windows ping packet size is smaller than on linux, hence we'll use the latter
Default linux ping packet size + IPv6 Header + ICMP Header

2021 Mar 21 22:01:42 FW-125852->192.168.100.254 Mar 21 23:01:42 FW-125852 FVE1032175935 firewall: msg_id="3000-0148" Allow Trusted Firebox 1300 icmp 20 128 192.168.100.99 192.168.100.254 8 0 id=1 seq=2  (Ping-00)
2021 Mar 21 22:01:42 FW-125852->192.168.100.254 Mar 21 23:01:42 FW-125852 FVE1032175935 firewall: msg_id="3000-0148" Allow Trusted Firebox 60 icmp 20 128 192.168.100.99 192.168.100.254 8 0 id=1 seq=2  (Ping-00)
-->
  <rule id="150080" level="8">
    <if_sid>150060</if_sid>
    <protocol>icmp</protocol>
    <field name="packetlen" type="pcre2">([0-9]{4,}|[1-9]0[5-9]|1[1-9][0-9]|[2-9][0-9]{2})</field>
    <description>Watchguard: firewall: $(action) from $(srcip) to $(dstip) using protocol $(protocol) [icmp] packet size is bigger than usual: $(packetlen)</description>
  </rule>

  <rule id="150081" level="13" frequency="10" timeframe="240" ignore="90">
    <if_matched_sid>150080</if_matched_sid>
    <same_srcip />
    <description>Watchguard: firewall: Possible $(protocol) tunnel attack from $(srcip) on interface $(src) to $(dstip) on interface $(dst)</description>
    <group>hidden_tunnel,pci_dss_10.6.1,pci_dss_11.4,gpg13_4.12,gdpr_IV_35.7.d,tsc_CC7.2,tsc_CC7.3,tsc_CC6.1,tsc_CC6.8,</group>
  </rule>
```




```xml
   <!--DNS hidden tunnel detection when too much packets are larger than standard DNS request size

IPv4 request size = 112
Adding IPv6 20 bytes header = 112 + 20 = 132
Domain names are max 63 characters
(63 letters).(63 letters).(63 letters).(62 letters) = 260 IPv4 (FQDN max length)
https://devblogs.microsoft.com/oldnewthing/20120412-00/?p=7873

Mar 21 23:43:20 FW-125852 FVE1032175935 firewall: msg_id="3000-0148" Allow Firebox External 156 udp 20 64 10.0.1.2 213.133.99.99 47189 53  (Any From Firebox-00)
Mar 21 23:47:28 FW-125852 FVE1032175935 firewall: msg_id="3000-0148" Allow Firebox External 60 udp 20 64 fe80::20c:29ff:fe59:7afa ac::d0:::1 47189 53  (Any From Firebox-00)
-->
  <rule id="150082" level="8">
    <if_sid>150060</if_sid>
    <dstport>53</dstport>
    <field name="packetlen" type="pcre2">([0-9]{4,}|[1-9]3[3-9]|1[4-9][0-9]|[2-9][0-9]{2})</field>
    <description>Watchguard: firewall: $(action) from $(srcip) to $(dstip) using protocol $(protocol):$(dstport) [dns] packet size is bigger than usual: $(packetlen)</description>
  </rule>

  <rule id="150083" level="13" frequency="10" timeframe="240" ignore="90">
    <if_matched_sid>150082</if_matched_sid>
    <same_srcip />
    <description>Watchguard: firewall: Possible $(protocol) tunnel attack from $(srcip) on interface $(src) to $(dstip) on interface $(dst)</description>
    <group>hidden_tunnel,pci_dss_10.6.1,pci_dss_11.4,gpg13_4.12,gdpr_IV_35.7.d,tsc_CC7.2,tsc_CC7.3,tsc_CC6.1,tsc_CC6.8,</group>
  </rule>
```




```xml
  <!--NTP hidden tunnel detection when too much packets are larger than standard NTP packet size

NTP request size IPv4 = 76
Adding IPv6 20 bytes header = 76 + 20 = 96

Apr 15 12:10:53 FW-125852 FVE1032175935 firewall: msg_id="3000-0148" Allow Trusted External 176 udp 20 63 192.168.100.250 162.159.200.123 48216 123  (Outgoing-00)
Apr 15 12:10:53 FW-125852 FVE1032175935 firewall: msg_id="3000-0148" Allow Trusted External 76 udp 20 63 fe80::20c:29ff:fe59:7afa ac::d0:::1 48216 123  (Outgoing-00)
-->

  <rule id="150084" level="8">
    <if_sid>150060</if_sid>
    <dstport>123</dstport>
    <field name="packetlen" type="pcre2">([1-9][0-9]{2,}|[2-9][0-9]|1[0-9])[0-9]{1}|([9-9][7-9])</field>
    <description>Watchguard: firewall: $(action) from $(srcip) to $(dstip) using protocol $(protocol):$(dstport) [ntp] packet size is bigger than usual: $(packetlen)</description>
  </rule>

  <rule id="150085" level="13" frequency="10" timeframe="240" ignore="90">
    <if_matched_sid>150084</if_matched_sid>
    <same_srcip />
    <description>Watchguard: firewall: Possible $(protocol) tunnel attack from $(srcip) on interface $(src) to $(dstip) on interface $(dst)</description>
    <group>hidden_tunnel,pci_dss_10.6.1,pci_dss_11.4,gpg13_4.12,gdpr_IV_35.7.d,tsc_CC7.2,tsc_CC7.3,tsc_CC6.1,tsc_CC6.8,</group>
  </rule>

  <rule id="150086" level="14" frequency="3" timeframe="240" ignore="90">
    <if_matched_group>hidden_tunnel</if_matched_group>
    <description>Watchguard: Possible multiple tunnel attacks ongoing. Please have a look</description>
    <group>pci_dss_10.6.1,pci_dss_11.4,gpg13_4.12,gdpr_IV_35.7.d,tsc_CC7.2,tsc_CC7.3,tsc_CC6.1,tsc_CC6.8,</group>
  </rule>

```




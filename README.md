# Black9

## Wazuh

### [Clasificación de Reglas](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html)

## WatchGuard

### [ID's de logs de WatchGuard](https://www.watchguard.com/help/docs/fireware/12/en-US/log_catalog/Log-Catalog_v12_6.pdf)

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
Tráfico normal denegado, nivel de alerta correcto, correspondiente a avisos de error. 

```xml
  <!-- Multiple denied generic traffic -->
  <rule id="150067" level="10" frequency="5" timeframe="300">
    <if_matched_group>packet_filter_deny</if_matched_group>
    <same_srcip />
    <description>Watchguard: firewall: Multiple denied traffic from same source $(srcip)</description>
    <group>firewall,access_denied,pci_dss_10.2.4,pci_dss_11.4,gpg13_4.12,gdpr_IV_35.7.d,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

```
Tráfico denegado múltiples veces desde la misma ip (para normal, App Control and IPS traffic), puede indicar un ataque, pero es altamente recomendable añadir un ignore. Valorar la etiqueta overwrite, pendiente comprobar su funcionamiento.  

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
Necesito saber qué considera WatchGuard como "tráfico hostil" para valorarlo mejor. 


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
```
<img width="594" alt="image" src="https://github.com/user-attachments/assets/1a3a1341-7853-4070-bf53-96663a31a709" />

<img width="904" alt="image" src="https://github.com/user-attachments/assets/608c2310-e827-41bd-abbe-915b42529650" />


```xml
  <rule id="150081" level="13" frequency="10" timeframe="240" ignore="90">
    <if_matched_sid>150080</if_matched_sid>
    <same_srcip />
    <description>Watchguard: firewall: Possible $(protocol) tunnel attack from $(srcip) on interface $(src) to $(dstip) on interface $(dst)</description>
    <group>hidden_tunnel,pci_dss_10.6.1,pci_dss_11.4,gpg13_4.12,gdpr_IV_35.7.d,tsc_CC7.2,tsc_CC7.3,tsc_CC6.1,tsc_CC6.8,</group>
  </rule>
```
### Alternativa
Generalmente los tunnel attacks o ataques de túnel se realizan desde una máquina dentro de la red interna hacia una máquina externa en internet. Esto se hace para evadir controles de seguridad y filtrados de firewall al encapsular tráfico malicioso dentro de protocolos permitidos. Internamente se producen muchos ping con un tamaño mayor al indicado, el cual no es malicioso muy probablemente. Puede deberse a MTU (Unidad máxima de transferencia), u otro motivo. Pendiente una investigación más exhaustiva de qué acciones se llevan a cabo en un ping que pueda llevar una cantidad de bytes tan grande. 
<img width="711" alt="image" src="https://github.com/user-attachments/assets/c4893ce6-675c-4f8e-9831-9c1eb9a33689" />

```xml 
<rule id="150079" level="5">
    <if_sid>150060</if_sid>
    <protocol>icmp</protocol>
    <field name="packetlen" type="pcre2">([0-9]{4,}|[1-9]0[5-9]|1[1-9][0-9]|[2-9][0-9]{2})</field>
    <field name="srcip" type="pcre2">^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)</field>
    <field name="dstip" type="pcre2">^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)</field>
    <description>Watchguard: firewall: $(action) from $(srcip) to $(dstip) using protocol $(protocol) [icmp] packet size is bigger than usual: $(packetlen) (Private IPs)</description>
</rule>

<rule id="150080" level="8">
    <if_sid>150060</if_sid>
    <protocol>icmp</protocol>
    <field name="packetlen" type="pcre2">([0-9]{4,}|[1-9]0[5-9]|1[1-9][0-9]|[2-9][0-9]{2})</field>
    <field name="srcip" type="pcre2">^(?!10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.).*</field>
    <field name="dstip" type="pcre2">^(?!10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.).*</field>
    <description>Watchguard: firewall: $(action) from $(srcip) to $(dstip) using protocol $(protocol) [icmp] packet size is bigger than usual: $(packetlen) (At least one public IP)</description>
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
<img width="953" alt="image" src="https://github.com/user-attachments/assets/1b7dcb9d-b351-4919-ad37-2ac68c834030" />


Consultas DNS que pueden ser perfectamente normales, están generando alertas de nivel 8. Se han generado alertas con paquetes hasta de tamaño 183. Se debería aumentar el tamaño mínimo por el que se genera la alerta, o reducir el nivel de alerta a nivel 3 y si se activa desde la misma IP muchas veces en poco tiempo, activarla. Aunque sería necesario una investigación más exhaustiva de cómo se comporta un DNS tunnel, tanto en tamaño de paquetes como en número de consultas / conexiones.



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

En este caso no parecen generarse alertas con tráfico legítimo en cantidades destacables, con lo que no considero necesario cambiar el límite de tamaño de paquetes. Pero si se desea, se puede cambiar el nivel de la alerta para que no muestre nada, o se muestre en un nivel menor, y crear otra alerta con este nivel o mayor. Además, no es correcta la descripción de tunnel attack. Simplemente están detectándose paquetes que podrían contener payloads maliciosos. Puede tratarse de un tunnel, un ataque de amplificación NTP.



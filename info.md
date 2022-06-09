## Columns
```python
Index(['Protocol', 'Flow Duration', 'Total Fwd Packets',
       'Total Length of Fwd Packets', 'Fwd Packet Length Mean',
       'Fwd Packet Length Std', 'Flow IAT Mean', 'Flow IAT Std',
       'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Min',
       'Fwd PSH Flags', 'Fwd URG Flags', 'Fwd Header Length', 'Fwd Packets/s',
       'Packet Length Mean', 'Packet Length Std', 'FIN Flag Count',
       'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
       'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
       'Average Packet Size', 'Avg Fwd Segment Size', 'Fwd Header Length.1',
       'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
       'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Init_Win_bytes_forward',
       'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std',
       'Idle Mean', 'Idle Std', 'Inbound'],
      dtype='object')
```

## notes
1. don't standardise Inbound and Protocol
2. must be safe to remove FWD URG Flags (all zero)
3. Protocol field include protocol numbers [17 - UDP, 6 - TCP, 0 - IPV6 HOP]
4. Remove Fwd Avg Bytes/Bulk	Fwd Avg Packets/Bulk	Fwd Avg Bulk Rate
5. Remove ECE Flag Count
6. Remove PSH Flag Count
7. Remove FIN Flag Count
8. in data labels, 1.0 means attack and 0.0 means not an attack
9. PI-CAT is a combined categorical attr for Protocol-Inbound
10. 

## Tshark fields for each cols
> Protocol: 
> 
> 
>

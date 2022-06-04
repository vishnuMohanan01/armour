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
3. ...

## Tshark fields for each cols
> Protocol: 
> 
> 
> 
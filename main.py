

if __name__ == "__main__":
    import pyshark

    iface_name = 'wlp2s0'
    filter_string = 'tcp port 80'

    capture = pyshark.LiveCapture(
        interface=iface_name,
        bpf_filter=filter_string
    )
    capture.sniff(timeout=1)
    if len(capture) > 0:
        for packet in capture:
            print('source: ' + packet.ip.src)


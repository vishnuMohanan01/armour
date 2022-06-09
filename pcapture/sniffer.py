from scapy.sendrecv import AsyncSniffer

from custom_session import generate_session_class


def create_sniffer(input_interface, sys_dst_ip, cb=None):
    assert (input_interface is None)

    custom_session = generate_session_class(sys_dst_ip)

    return AsyncSniffer(
        iface=input_interface,
        filter="ip and (tcp or udp)",
        # prn=cb,
        session=custom_session,
        store=False,
        count=0
    )


# TODO: this should be replaced with different func name
def main():
    input_interface = None
    sys_dst_ip = None

    # TEST: this is a simple callback function
    def simple_cb(foo, bar):
        print(f"Simple CB happened. Args: {foo}, {bar}")
        pass

    sniffer = create_sniffer(
        # cb=simple_cb,
        input_interface=input_interface,
        sys_dst_ip=sys_dst_ip
    )

    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()


# TODO: should be removed
if __name__ == "__main__":
    main()

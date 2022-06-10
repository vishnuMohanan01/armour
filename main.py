from scapy.sendrecv import AsyncSniffer

from firewall.utils.model_utils import load_clf_model
from pcapture.custom_session import generate_session_class


def create_sniffer(input_interface, sys_ip):
    assert (input_interface is None)

    custom_session = generate_session_class(sys_ip)

    return AsyncSniffer(
        iface=input_interface,
        filter="ip and (tcp or udp)",
        prn=None,
        session=custom_session,
        store=False,
        count=0
    )


def main():
    input_interface = None
    sys_ip = None

    sniffer = create_sniffer(
        # cb=simple_cb,
        input_interface=input_interface,
        sys_ip=sys_ip
    )

    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()


if __name__ == "__main__":
    """This is the entry point of A-R-M-O-U-R
    """
    clf_model = load_clf_model("rf_28")
    main()

import argparse

from scapy.sendrecv import AsyncSniffer

from firewall.utils.model_utils import load_clf_model
from pcapture.custom_session import generate_session_class


def create_sniffer(clf_model, input_interface, sys_ip):
    assert (input_interface is None)

    custom_session = generate_session_class(clf_model, sys_ip)

    return AsyncSniffer(
        iface=input_interface,
        filter="ip and (tcp or udp)",
        prn=None,
        session=custom_session,
        store=False,
        count=0
    )


def get_commandline_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip',
                        action='store',
                        help='public IPv4 address of the current system',
                        required=True)

    return parser


def main() -> None:
    """
    1. get cmd args
    2. loads model
    3. creates and triggers sniffer
    :return: None
    """

    # parse cmd args
    commandline_parser = get_commandline_parser()
    cmd_args = commandline_parser.parse_args()

    """Armour Settings
    """
    input_interface = None
    sys_ip = cmd_args.ip
    clf_model = load_clf_model("rf_28")

    """created and manages sniffer
    """
    sniffer = create_sniffer(
        clf_model=clf_model,
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
    """Entry point of A-R-M-O-U-R
    """
    main()

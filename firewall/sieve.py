class Firewall:
    def __init__(self, clf_model, packet_info) -> None:
        """

        :param clf_model: sklearn model instance
        :param packet_info: dictionary containing all attrs required fir classification
        :return: None
        """
        self.__clf_model = clf_model

        self.packet_info = packet_info

    def filter(self) -> None:
        """
        triggers clf funcs and blacklisting procedures
        :return: None
        """
        


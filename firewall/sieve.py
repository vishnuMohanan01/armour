import pandas as pd

from firewall.blacklist.blacklist_utils import blacklist
from firewall.classifier.pipeline import create_pipeline


class Firewall:
    def __init__(self, clf_model) -> None:
        """

        :param clf_model: sklearn model instance
        :return: None
        """
        self.__clf_model = clf_model
        self.packet_info = None
        self.__pipeline = create_pipeline()
        self.__X = None
        self.__ip_dict = {}

    def filter(self, packet_info) -> None:
        """
        triggers clf funcs and blacklisting procedures
        :param packet_info: dictionary containing all attrs required fir classification

        :return: None
        """
        self.packet_info = pd.DataFrame(packet_info, index=[0])

        self.__X = self.__pipeline.fit_transform(self.packet_info)

        """predicted results will look like
        [1.] and [0.]
        
        1 - attack
        0 - not an attack
        """
        # DO EVERYTHING HERE
        # print(f"{self.packet_info['src_ip'].values[0]}:{self.packet_info['src_port'].values[0]} - {self.__clf_model.predict(self.__X)}")
        y = self.__clf_model.predict(self.__X)

        if y[0] == 1:
            if not self.__ip_dict[self.packet_info['src_ip'].values[0]]:
                self.__ip_dict[self.packet_info['src_ip'].values[0]] = 1
            else:
                self.__ip_dict[self.packet_info['src_ip'].values[0]] += 1

        if self.__ip_dict[self.packet_info['src_ip'].values[0]] > 20:
            blacklist(self.packet_info['src_ip'].values[0])

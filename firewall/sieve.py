import pandas as pd

from firewall.classifier.pipeline import create_pipeline


class Firewall:
    def __init__(self, clf_model, packet_info) -> None:
        """

        :param clf_model: sklearn model instance
        :param packet_info: dictionary containing all attrs required fir classification
        :return: None
        """
        self.__clf_model = clf_model
        self.__pipeline = None
        self.__X = None

        self.packet_info = pd.DataFrame(packet_info, index=[0])

    def filter(self) -> None:
        """
        triggers clf funcs and blacklisting procedures
        :return: None
        """
        self.__pipeline = create_pipeline()
        self.__X = self.__pipeline.fit_transform(self.packet_info)

        """predicted results will look like
        [1.] and [0.]
        
        1 - attack
        0 - not an attack
        """
        print(self.__clf_model.predict(self.__X))

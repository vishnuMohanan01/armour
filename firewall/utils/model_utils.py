import os.path
import pickle as pkl

from firewall.classifier.constants import CATEGORICAL_COLS, LABEL_COLS, NUMERICAL_COLS


def load_clf_model(model_name):
    """

    :param model_name: name of model present in /models without the .pkl extension
    :return: sklearn model instance
    """
    with open(os.path.join("..", "models", f"{model_name}.pkl"), 'rb') as f:
        return pkl.load(f)


def get_req_cols() -> dict:
    return {
        'label_cols': LABEL_COLS,
        'numerical_cols': NUMERICAL_COLS,
        'categorical_cols': CATEGORICAL_COLS
    }

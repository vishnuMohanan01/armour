import os.path
import pickle as pkl


def load_clf_model(model_name):
    """

    :param model_name: name of model present in /models without the .pkl extension
    :return: sklearn model instance
    """
    with open(os.path.join("..", "models", f"{model_name}.pkl"), 'rb') as f:
        return pkl.load(f)

import yaml
import os

def load_config(filepath: str = 'algorithms.yaml') -> dict | None:
    """
    Charge la configuration depuis un fichier YAML spécifié.

    Args:
        filepath (str): Le chemin vers le fichier de configuration YAML.
                        Par défaut 'algorithms.yaml'.

    Returns:
        dict | None: Un dictionnaire contenant la configuration chargée
                     si le fichier est trouvé et valide.
                     Retourne None si le fichier n'est pas trouvé ou
                     si une erreur de parsing YAML survient.
    """
    if not os.path.exists(filepath):
        print(f"Erreur : Le fichier de configuration '{filepath}' n'a pas été trouvé.")
        return None
    try:
        # 'encoding="utf-8"' est recommandé pour la compatibilité
        with open(filepath, 'r', encoding='utf-8') as file_stream:
            # Utiliser safe_load est plus sûr que load car il évite
            # l'exécution de code arbitraire potentiellement présent dans le YAML.
            config_data = yaml.safe_load(file_stream)
            if config_data is None:
                 # Handle empty file case or file with just comments
                 print(f"Attention : Le fichier de configuration '{filepath}' est vide ou ne contient que des commentaires.")
                 return {} # Retourne un dictionnaire vide pour un fichier vide
            return config_data
    except yaml.YAMLError as e:
        print(f"Erreur : Impossible de parser le fichier YAML '{filepath}'.")
        # Affiche des détails sur l'erreur de parsing si disponibles
        if hasattr(e, 'problem_mark'):
            mark = e.problem_mark
            print(f"  Erreur à la ligne {mark.line + 1}, colonne {mark.column + 1}")
        if hasattr(e, 'problem'):
             print(f"  Problème: {e.problem}")
        # Vous pouvez choisir de logger l'exception complète ici si nécessaire
        # import traceback
        # traceback.print_exc()
        return None
    except Exception as e:
        # Capture d'autres erreurs potentielles (ex: problèmes de permissions)
        print(f"Erreur inattendue lors de la lecture de '{filepath}': {e}")
        return None
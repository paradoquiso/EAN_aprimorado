"""
Módulo src do sistema EAN_aprimorado
"""

# Importações necessárias para o módulo
__version__ = "1.0.0"
__author__ = "EAN_aprimorado Team"

# Facilitar importações
try:
    from .main import app
    __all__ = ['app']
except ImportError:
    # Em caso de erro de importação, não falhar completamente
    __all__ = []

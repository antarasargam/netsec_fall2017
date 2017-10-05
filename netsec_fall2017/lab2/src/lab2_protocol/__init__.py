import playground
from .Server import Serverfactory
from .Client import Clientfactory

lab2Connector = playground.Connector(protocolStack=(Clientfactory, Serverfactory))
playground.setConnector("lab2_protocol", lab2Connector)


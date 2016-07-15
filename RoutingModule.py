from Queue import Queue
import thread
import logging

class RoutingModule(object):
	"""docstring for RoutingModule"""
	def __init__(self,switchInstance):
		super(RoutingModule, self).__init__()
		self.packetQueue = Queue()
		self.switchInstance = switchInstance
		thread.start_new_thread( self.routingModuleDecisionMaker,() )
		self.RoutingModuleLogger  =  self.get_logger("RoutingModule")
		# self.RoutingModuleLogger.basicConfig(filename="RoutingModule.log", level=logging.INFO)

	def findOutputPort(self,destinationMAC,sourceMAC,interface, inputPort):
		if inputPort == 1:
			return 2
		return 1
	def queuePacketForDecision(self,packetInfo):
		self.RoutingModuleLogger.info("queuePacketForDecision " +str(packetInfo))
		self.packetQueue.put(packetInfo)
	def routingModuleDecisionMaker(self):
		self.RoutingModuleLogger.info("Starting Routing Module decision maker")
		while True:
			packetToConsider = self.packetQueue.get()
			self.RoutingModuleLogger.info("Packet arrived for Decision " +str(packetToConsider))
			port = -1
			routingModuleDecisionMaker = RoutingDecisionVariables("","","",port,packetToConsider.packet)
			self.switchInstance.packetDecision(routingModuleDecisionMaker)
			self.RoutingModuleLogger.info("Packet Decision Sent " + str(routingModuleDecisionMaker))

	def get_logger(self,name=None):
	    default = "__app__"
	    formatter = logging.Formatter('%(levelname)s: %(asctime)s %(funcName)s(%(lineno)d) -- %(message)s',
	                              datefmt='%Y-%m-%d %H:%M:%S')
	    log_map = {"RoutingModule": "RoutingModule.log"}
	    if name:
	        logger = logging.getLogger(name)
	    else:
	        logger = logging.getLogger(default)
	    fh = logging.FileHandler(log_map[name])
	    fh.setFormatter(formatter)
	    logger.addHandler(fh)
	    logger.setLevel(logging.INFO)
	    return logger
class RoutingDecisionVariables(object):
	"""docstring for RoutingDecisionVariables"""
	def __init__(self,destinationMAC,sourceMAC,interface, inputPort,packet):
		super(RoutingDecisionVariables, self).__init__()
		self.destinationMAC = destinationMAC
		self.sourceMAC = sourceMAC
		self.interface  = interface
		self.inputPort = inputPort
		self.packet = packet
	def __str__(self):
		if self is None:
			return "\n\nPacket is None\n\n"
		return "\nDestination MAC " + self.destinationMAC + "\nSource MAC " +self.sourceMAC+"\nInterface " +self.interface+"\nInput Port " + str(self.inputPort)

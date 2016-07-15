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
		logging.basicConfig(filename="RoutingModule.log", level=logging.INFO)

	def findOutputPort(self,destinationMAC,sourceMAC,interface, inputPort):
		if inputPort == 1:
			return 2
		return 1
	def queuePacketForDecision(self,packetInfo):
		logging.info("queuePacketForDecision " +str(packetInfo))
		self.packetQueue.put(packetInfo)
	def routingModuleDecisionMaker(self):
		logging.info("Starting Routing Module decision maker")
		while True:
			packetToConsider = self.packetQueue.get()
			logging.info("Packet arrived for Decision " +str(packetToConsider))
			port = 1
			routingModuleDecisionMaker = RoutingDecisionVariables("","","",port,packetToConsider.packet)
			self.switchInstance.packetDecision(routingModuleDecisionMaker)
			logging.info("Packet Decision Sent " + str(routingModuleDecisionMaker))

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

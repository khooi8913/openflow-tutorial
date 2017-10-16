
from mininet.topo import Topo

class AdvancedTopo( Topo ):
	
	def __init__(self):

		Topo.__init__(self)

		#Add switch
		switchOne = self.addSwitch('s1')
		switchTwo = self.addSwitch('s2')

		#Add hosts
		firstHost = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
		secondHost = self.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
		thirdHost = self.addHost('h3', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')

		#Add links
		self.addLink (switchOne, firstHost)
		self.addLink (switchOne, secondHost)
		self.addLink (switchTwo, thirdHost)
		self.addLink (switchOne, switchTwo)

topos = {'advancedtopo' : (lambda: AdvancedTopo())}

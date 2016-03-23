import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowKey;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 * ScannerFinder is used to read through a pcap file and print the IP addresses that send more than three times as many SYN requests as the SYNACK that they receive 
 * Tyler Wright
 * March 22, 2015
 * 
 */
public class ScannerFinder {
	private final String FILENAME = "lbl-internal.20041004-1305.port002.dump.pcap";	//file path for pcap dump file
	private final StringBuilder errbuf = new StringBuilder();
	private final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
	
	
	//method for parsing pcap file and printing out up address of possible port scanners
	public void read() {
		//if pcap empty, return 
		if (pcap == null) {
			System.err.println(errbuf); // Error is stored in errbuf if any
			return;
		}
		HashMap ipHash = new HashMap(); 	//hash map to store ip addresses with sy and ack numbers 
		final PcapPacket packet = new PcapPacket(JMemory.POINTER);
		final Tcp tcp = new Tcp();
		//loop through entire file, getting each packet
		pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {
			final Tcp tcp = new Tcp();
			final Ip4 ip = new Ip4();
			Payload payload = new Payload();
			//get next packet
			public void nextPacket(JPacket packet, StringBuilder errbuf) {
				Tcp tcp = new Tcp();

				byte[] sIP = new byte[4];
				byte[] dIP = new byte[4];
				String sourceIP = "";
				String destIP = "";
				//if packet has ip and tcp header, examine further
				if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
					sIP = packet.getHeader(ip).source();
					sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);	//source ip address as string 
					dIP = packet.getHeader(ip).destination();
					destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);	//destination ip address as string 
					//if packet contains only SYN, increment value for sender IP
					if (tcp.flags_SYN() && !tcp.flags_ACK()) {
						if (ipHash.containsKey(sourceIP)) {
							int synVal = (int)(ipHash.get(sourceIP)); 
							synVal++; 
							ipHash.put(sourceIP, synVal); 
							if ((int)(ipHash.get(sourceIP)) == 0) {
								ipHash.remove(sourceIP); 
							}
						} else {
							ipHash.put(sourceIP, 1);
						}
					//packet contains SYN and ACK, decrement value for receiving IP
					} else if (tcp.flags_SYN()) {
						if (ipHash.containsKey(destIP)) {
							int synVal = (int)(ipHash.get(destIP)); 
							synVal--; 
							ipHash.put(destIP, synVal); 
							if ((int)(ipHash.get(destIP)) == 0) {
								ipHash.remove(destIP); 
							}
						} else {
							ipHash.put(destIP, -1);
						}
					}
				}
			}
			
		}, errbuf);
		//for each IP, print those with > 3 times syn to synack
		for (Object key : ipHash.keySet()) {
			if ((int)ipHash.get(key) > 2) {
				System.out.println(key);
			}
		}
		pcap.close();
	}
	
	public static void main(String[] args) {
		ScannerFinder s = new ScannerFinder(); 
		s.read(); 
	}
}
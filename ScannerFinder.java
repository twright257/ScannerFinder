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
 * This example demonstrates various usage scenerios for jNetPcap API. The test
 * file used in this example can be found under the "tests" directory located
 * under the root installation directory of the source package. The tests
 * directory is not normally provided with binary distribution of jnetpcap. The
 * test file contains 483 packets most of which are http or tcp segments.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class ScannerFinder {
	private final String FILENAME = "lbl-internal.20041004-1305.port002.dump.pcap";
	private final StringBuilder errbuf = new StringBuilder();
	private final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
	
	public void read() {
		if (pcap == null) {
			System.err.println(errbuf); // Error is stored in errbuf if any
			return;
		}
		HashMap ipHash = new HashMap(); 
		final PcapPacket packet = new PcapPacket(JMemory.POINTER);
		final Tcp tcp = new Tcp();
		pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {

			final Tcp tcp = new Tcp();
			final Ip4 ip = new Ip4();
			Payload payload = new Payload();

			public void nextPacket(JPacket packet, StringBuilder errbuf) {
				Tcp tcp = new Tcp();

				byte[] sIP = new byte[4];
				byte[] dIP = new byte[4];
				String sourceIP = "";
				String destIP = "";
				if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
					sIP = packet.getHeader(ip).source();
					sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
					dIP = packet.getHeader(ip).destination();
					destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
					
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
//						System.out.println("SYN");
//						System.out.println(ipHash.get(sourceIP));
//						System.out.println("Source IP: " + sourceIP);
//						System.out.println("Destination IP: " + destIP);
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
//						System.out.println("SYNACK");
//						System.out.println(ipHash.get(sourceIP));
//						System.out.println("Source IP: " + sourceIP);
//						System.out.println("Destination IP: " + destIP);
					}
				}
			}
			
		}, errbuf);
		for (Object key : ipHash.keySet()) {
			if ((int)ipHash.get(key) >= 2) {
				System.out.println(key);
			}
		}
		/*
		 * Now that we have captured our 10 packets, lets use Pcap.nextEx to get
		 * the next 5 packets. We will also reset the frame number back to 0
		 * just so we can see how its done. Each scanner keeps track of its own
		 * frame numbers, so we want to get the default one, for this thread,
		 * and change it there.
		 */

		/*
		 * We still haven't read all the packets from our offline file. Here is
		 * an easier way to retrieve all the packets while grouping them into
		 * flows. jNetPcap provides a neat little class that does all of the
		 * above work for us. Its called JFlowMap, not only that it implements a
		 * JPacketHandler interface suitable for usage with Pcap.loop or
		 * Pcap.dispatch calls and it will add all packets received into
		 * appropriate flows.
		 */
		JFlowMap superFlowMap = new JFlowMap();

		/*
		 * So lets finish this file off, and read the remaining packets into our
		 * new superFlowMap and do a pretty print of all the flows it finds. The
		 * 3rd argument to Pcap.loop is unused so we just set it to null.
		 * Pcap.LOOP_INFINITE flag tells the Pcap.loop method to read all the
		 * packets until the end of file. Since we already read some packets,
		 * this will read remaining packets from the current position in the
		 * file until the end.
		 */
		// pcap.loop(100000, superFlowMap, null);

		// System.out.printf("superFlowMap::%s%n", superFlowMap);

		/*
		 * Now we have read the remaining packets and we no longer need to keep
		 * the pcap file open.
		 */
		pcap.close();
	}
	
	public static void main(String[] args) {
		ScannerFinder s = new ScannerFinder(); 
		s.read(); 
	}
}

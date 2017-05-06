/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Lab5IDS;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowKey;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 *
 * @author alex
 */
public class Lab5IDS {

    private static Boolean found = false;
    private static String[] policy = new String[9];
    private static ArrayList<String[]> streamList = new ArrayList();
    private static String packetStream = "";

    /**
     * Various examples
     *
     * @param args none expected
     * @throws java.io.UnsupportedEncodingException
     * @throws java.security.NoSuchAlgorithmException
     */
    public static void main(String[] args) throws UnsupportedEncodingException,
            NoSuchAlgorithmException {

        String home = System.getProperty("user.home") + "/";
        String traceFile = "Downloads/trace4.pcap";
        String policyFile = "Policy3.txt";

        if (args.length == 2) {
            policyFile = args[0];
            traceFile = args[1];
            loadPolicy(policyFile);
        }

        final String FILENAME = home + traceFile;
        System.out.println("Loading trace " + FILENAME);
        if (args.length == 0) {
            String path;
            Scanner in = new Scanner(System.in);
            path = policyFile;
            if (path.startsWith("~")) {
                path = path.substring(1);
            }
            if (!path.startsWith("/")) {
                path = "/" + path;
            }
            loadPolicy(path);
        } else {

        }

        final StringBuilder errbuf = new StringBuilder();

        final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);

        if (pcap == null) {
            System.out.println("pcap is null.");
            System.err.println(errbuf); // Error is stored in errbuf if any  
            return;
        }
        // loops through each packet
        pcap.loop(pcap.LOOP_INFINITE,
                new JPacketHandler<StringBuilder>() {

            final Tcp tcp = new Tcp();
            final Http http = new Http();

            public void nextPacket(JPacket packet, StringBuilder errbuf) {
                if (policy[2] != null
                        && policy[2].equals("stateful")) {
                    buildStream(packet);
                } else {
                    statelessTest(packet);
                }
            }
        }, errbuf);
        if (policy[2] != null
                && policy[2].equals("stateful")) {
            statefulTest();
        }
        if (!found) {
            System.out.println("No attacks found.");
        }
    }

    /**
     * if an intrusion is detected, call this to display warning
     */
    public static void warning() {
        System.out.println(policy[1] + " found.");
        found = true;
    }

    /**
     * builds packet stream for stateful tests.
     * @param packet 
     */
    public static void buildStream(JPacket packet) {
        final Ip4 ip = new Ip4();
        final Tcp tcp = new Tcp();
        final Udp udp = new Udp();
        packet.getHeader(ip);
        byte[] attacker = ip.source();
        String attackerIp = org.jnetpcap.packet.format.FormatUtils.ip(attacker);

        for (String[] sList : streamList) {
            if (attackerIp.equals(sList[0])) {
                if (packet.hasHeader(tcp)) {
                    String tcpPay = new String(tcp.getPayload());
                        sList[1] = sList[1].concat(tcpPay.replaceAll("  ", ""));
                        return;
                    
                    }
                    if (packet.hasHeader(udp)) {
                        String udpPay = new String(udp.getPayload());
                        sList[2] = sList[2].concat(udpPay.replaceAll("  ", ""));
                        return;
                    }
                }
            }

            String[] newStream = new String[3];
            newStream[0] = attackerIp;
            if (packet.hasHeader(tcp)) {
                newStream[1] = new String(tcp.getPayload());
            } else {
                newStream[1] = "";
            }
            if (packet.hasHeader(udp)) {
                newStream[2] = new String(udp.getPayload());
            } else {
                newStream[2] = "";
            }
            streamList.add(newStream);

        }
    
    /**
     * runs a test on each individual packet. (stateless)
     * @param packet 
     */
    public static void statelessTest(JPacket packet) {
        final Ip4 ip = new Ip4();
        final Tcp tcp = new Tcp();
        final Udp udp = new Udp();
        if (packet.hasHeader(tcp)) {
            // check host ip
            packet.getHeader(ip);
            byte[] host = ip.destination();
            String hostIp = org.jnetpcap.packet.format.FormatUtils.ip(host);
            if (!hostIp.equals(policy[0])) {
                return;

            }
            // check host port
            int hostPort = tcp.destination();
            if (!policy[4].equals("any")) {
                int iHost = Integer.parseInt(policy[4]);
                if (hostPort != iHost) {
                    return;
                }
            }
            String s = new String();
            s.replaceAll("\"", "");
            // check attacer port
            int attackerPort = tcp.source();
            if (!policy[5].equals("any")) {
                int iAttacker = Integer.parseInt(policy[5]);
                if (attackerPort != iAttacker) {
                    return;
                }
            }

            // check payload
            Pattern hostRagex = Pattern.compile(policy[8]);
            Matcher m = hostRagex.matcher(new String(tcp.getPayload()));
            if (m.find()) {
                warning();
            }
        }

        if (packet.hasHeader(udp)) {
            // check host ip
            packet.getHeader(ip);
            byte[] host = ip.destination();
            String hostIp = org.jnetpcap.packet.format.FormatUtils.ip(host);
            if (!hostIp.equals(policy[0])) {
                return;

            }
            // check host port
            int hostPort = udp.destination();
            if (!policy[4].equals("any")) {
                int iHost = Integer.parseInt(policy[4]);
                if (hostPort != iHost) {
                    return;
                }
            }
            String s = new String();
            s.replaceAll("\"", "");
            // check attacer port
            int attackerPort = udp.source();
            if (!policy[4].equals("any")) {
                int iAttacker = Integer.parseInt(policy[5]);
                if (!policy[5].equals("any")
                        && attackerPort != iAttacker) {
                    return;
                }
            }

            // check payload
            Pattern hostRagex = Pattern.compile(policy[8]);
            Matcher m = hostRagex.matcher(new String(udp.getPayload()));
            if (m.find()) {
                warning();
            }
        }

    }

    /**
     * runs a test on the packet stream. (stateful)
     */
    public static void statefulTest() {
        for (String[] sList : streamList) {

            // check payload
//            Pattern hostRagex = Pattern.compile("\x90");
            Pattern hostRagex = Pattern.compile(policy[8]);
            Matcher m = hostRagex.matcher(sList[1]);
            if (m.find()) {
                warning();
            }
            if ((m = hostRagex.matcher(sList[2])).find()) {

                warning();
            }
        }

    }

    /**
     * loads the policy file, and reads in policy rules
     * @param path
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException 
     */
    public static void loadPolicy(String path) throws
            UnsupportedEncodingException, NoSuchAlgorithmException {
        System.out.print("Loading policy ");
        FileReader fr = null;
        BufferedReader br = null;
        String home = System.getProperty("user.home");
        File absolute = new File(home + path);
        System.out.println(absolute.getAbsolutePath());

        try {
            fr = new FileReader(absolute);
            br = new BufferedReader(fr);
            String currentLine;
            int f = 7;
            int t = 8;

            while ((currentLine = br.readLine()) != null) {
                Pattern hostRagex = Pattern.compile("(host=)(.*)");
                Pattern nameRagex = Pattern.compile("(name=)(.*)");
                Pattern typeRagex = Pattern.compile("(type=)(.*)");
                Pattern protoRagex = Pattern.compile("(proto=)(.*)");
                Pattern host_portRagex = Pattern.compile("(host_port=)(.*)");
                Pattern attacker_portRagex = Pattern.compile("(attacker_port=)"
                        + "(.*)");
                Pattern attackerRagex = Pattern.compile("(attacker=)(.*)");
                Pattern from_hostRagex = Pattern.compile("(from_host=)(.*)");
                Pattern to_hostRagex = Pattern.compile("(to_host=)(.*)");
                Matcher m = hostRagex.matcher(currentLine);
                if (m.find() && !m.group(2).startsWith("\"")) {
                    policy[0] = m.group(2);
                } else if ((m = nameRagex.matcher(currentLine)).find()) {
                    policy[1] = m.group(2);
                } else if ((m = typeRagex.matcher(currentLine)).find()) {
                    policy[2] = m.group(2);
                } else if ((m = protoRagex.matcher(currentLine)).find()) {
                    policy[3] = m.group(2);
                } else if ((m = host_portRagex.matcher(currentLine)).find()) {
                    policy[4] = m.group(2);
                } else if ((m = attacker_portRagex.matcher(currentLine)).find()) {
                    policy[5] = m.group(2);
                } else if ((m = attackerRagex.matcher(currentLine)).find()) {
                    policy[6] = m.group(2);
                } else if ((m = from_hostRagex.matcher(currentLine)).find()) {
                    if (policy[7] == null) {
                        policy[7] = m.group(2).replaceAll("\"", "");
                    } else {
                        policy[7] = policy[7].concat(".*"
                                + m.group(2).replaceAll("\"", ""));
                    }
                } else if ((m = to_hostRagex.matcher(currentLine)).find()) {
                    if (policy[8] == null) {
                        policy[8] = m.group(2).replaceAll("\"", "");
                    } else {
                        policy[8] = policy[8].concat(".*"
                                + m.group(2).replaceAll("\"", ""));
                    }
                }
                m = to_hostRagex.matcher(currentLine);
                if (m.find() && policy[8] == null) {
                    policy[8] = m.group(2).replaceAll("\"", "");
                }
            }
        } catch (IOException e) {
        } finally {
            try {
                if (br != null) {
                    br.close();
                }
                if (fr != null) {
                    fr.close();
                }
            } catch (IOException ex) {
            }
        }
    }
}

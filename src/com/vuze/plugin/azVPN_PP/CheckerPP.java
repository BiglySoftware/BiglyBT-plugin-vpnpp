/*
 * Copyright (C) Azureus Software, Inc, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details ( see the LICENSE file ).
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package com.vuze.plugin.azVPN_PP;

import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.net.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import com.biglybt.core.Core;
import com.biglybt.core.util.AESemaphore;
import com.biglybt.core.util.Debug;
import com.biglybt.pif.PluginConfig;
import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.utils.*;

import com.biglybt.core.CoreFactory;
import com.biglybt.core.networkmanager.admin.*;
import com.biglybt.net.udp.uc.PRUDPPacketHandler;
import com.biglybt.net.udp.uc.PRUDPPacketHandlerFactory;
import com.biglybt.net.udp.uc.PRUDPReleasablePacketHandler;

public class CheckerPP
{
	private static final char CHAR_GOOD = '\u2714';

	private static final char CHAR_BAD = '\u2716';

	private static final char CHAR_WARN = '\u2318';

	public static final int STATUS_ID_OK = 0;

	public static final int STATUS_ID_BAD = 1;

	public static final int STATUS_ID_WARN = 2;

	private static final boolean rebindNetworkInterface = true;

	private UTTimer timer;

	private PluginConfig config;

	private PluginInterface pi;

	private List<CheckerPPListener> listeners = new ArrayList<CheckerPPListener>(
			1);

	private String lastProtocolAddresses = "";

	private String lastPortCheckStatus = "";

	private boolean checkingPortBinding;

	private LocaleUtilities texts;

	private InetAddress testSocketAddress;

	private InetAddress vpnIP;

	private int currentStatusID = -1;

	public CheckerPP(PluginInterface pi) {
		this.pi = pi;
		this.config = pi.getPluginconfig();
		this.texts = pi.getUtilities().getLocaleUtilities();

		try {
			testSocketAddress = InetAddress.getByAddress(new byte[] {
				1,
				1,
				1,
				1
			});
		} catch (UnknownHostException e) {
		}

	}

	public void destroy() {
		if (timer != null) {
			timer.destroy();
			timer = null;
		}
		listeners.clear();
	}

	protected void buildTimer() {
		if (timer != null) {
			timer.destroy();
			timer = null;
		}
		int mins = config.getPluginIntParameter(PluginPP.CONFIG_CHECK_MINUTES);
		if (mins == 0) {
			return;
		}
		timer = pi.getUtilities().createTimer("PP");
		timer.addPeriodicEvent(mins * 60 * 1000l, new UTTimerEventPerformer() {
			@Override
			public void perform(UTTimerEvent event) {
				try {
					portBindingCheck();
				} catch (Throwable t) {
					t.printStackTrace();
				}
			}
		});
	}

	public String portBindingCheck() {
		synchronized (this) {
			if (checkingPortBinding) {
				return lastPortCheckStatus;
			}
			checkingPortBinding = true;
		}

		CheckerPPListener[] triggers = listeners.toArray(new CheckerPPListener[0]);
		for (CheckerPPListener l : triggers) {
			try {
				l.portCheckStart();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		StringBuilder sReply = new StringBuilder();

		try {
			int newStatusID = findBindingAddress(sReply);

			boolean doPortForwarding = config.getPluginBooleanParameter(
					PluginPP.CONFIG_DO_PORT_FORWARDING);

			if (doPortForwarding) {
				if (pi.getUtilities().isWindows()) {
					newStatusID = portForwardingCheckWin(newStatusID, sReply);
				} else {
					newStatusID = portForwardingCheckNonWin(newStatusID, sReply);
				}
			}

			if (newStatusID != -1) {
				currentStatusID = newStatusID;
			}
			String msgID = null;
			if (newStatusID == STATUS_ID_BAD) {
				msgID = "pp.topline.bad";
			} else if (newStatusID == STATUS_ID_OK) {
				msgID = "pp.topline.ok";
			} else if (newStatusID == STATUS_ID_WARN) {
				msgID = "pp.topline.warn";
			}
			if (msgID != null) {
				sReply.insert(0, texts.getLocalisedMessageText(msgID) + "\n");
			}

		} catch (Throwable t) {
			t.printStackTrace();
			PluginPP.log(t.toString());
		}

		lastPortCheckStatus = sReply.toString();

		triggers = listeners.toArray(new CheckerPPListener[0]);
		for (CheckerPPListener l : triggers) {
			try {
				l.portCheckStatusChanged(lastPortCheckStatus);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		synchronized (this) {
			checkingPortBinding = false;
		}
		return lastPortCheckStatus;
	}

	private int portForwardingCheckWin(int newStatusID, StringBuilder sReply) {
		LineNumberReader lnr = null;

		try {
			PluginConfig pluginConfig = pi.getPluginconfig();
			int coreTCPPort = pluginConfig.getCoreIntParameter(
					PluginConfig.CORE_PARAM_INT_INCOMING_TCP_PORT);
			int coreUDPPort = pluginConfig.getCoreIntParameter(
					PluginConfig.CORE_PARAM_INT_INCOMING_UDP_PORT);

			Process p = Runtime.getRuntime().exec(new String[] {
				"reg",
				"query",
				"HKLM\\SYSTEM\\CurrentControlSet\\services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules",
				"/t",
				"REG_SZ",
				"/f",
				"\"Perfect Privacy\""
			});

			lnr = new LineNumberReader(new InputStreamReader(p.getInputStream()));

			while (true) {

				String line = lnr.readLine();

				if (line == null) {

					break;
				}

				if (line.contains("Perfect Privacy") && line.contains("LPort")) {

					String[] split = line.split("\\|");
					int port = -1;
					for (String entry : split) {
						if (entry.startsWith("LPort=")) {
							int lport = Integer.parseInt(entry.substring(6));
							if (lport == coreTCPPort && lport == coreUDPPort) {
								port = lport;
								break;
							}
							if (lport > port) {
								port = lport;
							}
						}
					}

					if (port > 0) {
						addReply(sReply, CHAR_GOOD, "pp.port.in.registry", new String[] {
							Integer.toString(port)
						});
						changePort(port, sReply);
						return newStatusID;
					} else {
						return portForwardingCheckNonWin(newStatusID, sReply);
					}

				}
			}

		} catch (Throwable e) {
		} finally {
			if (lnr != null) {
				try {
					lnr.close();
				} catch (Throwable e) {
				}
			}
		}
		return portForwardingCheckNonWin(newStatusID, sReply);
	}

	private int portForwardingCheckNonWin(int newStatusID, StringBuilder sReply) {
		/*
		 * From Perfect Privacy's Javascript Port Calcaulator:
		
		function check() {
		str = jQuery('#form_ip_octet_3').val();
		if (str == "") {
		    return;
		}
		number = str.charAt(str.length - 1);
		lastpart = jQuery('#form_ip_octet_4').val();
		if (lastpart == "") {
		    return;
		}
		if (lastpart.length == 2) {
		    lastpart = "0" + lastpart;
		}
		if (lastpart.length == 1) {
		    lastpart = "00" + lastpart;
		}
		port1 = "1" + number + lastpart;
		port2 = "2" + number + lastpart;
		port3 = "3" + number + lastpart;
		
		jQuery('#ports').html("<td>" + port1 + "</td><td>" + port2 + "</td><td>" + port3 + "</td>");
		}
		 */

		if (vpnIP != null) {
			byte[] address = vpnIP.getAddress();
			int number = (address[2] & 0xff) % 10; // last digit
			String lastPart = "" + (address[3] & 0xff);
			if (lastPart.length() == 2) {
				lastPart = "0" + lastPart;
			}
			if (lastPart.length() == 1) {
				lastPart = "00" + lastPart;
			}

			String portString = "1" + number + lastPart;
			int port = Integer.parseInt(portString);

			addReply(sReply, CHAR_GOOD, "pp.port.calculated", new String[] {
				Integer.toString(port)
			});
			changePort(port, sReply);
		} else {
			if (newStatusID != STATUS_ID_BAD) {
				newStatusID = STATUS_ID_WARN;

				addReply(sReply, CHAR_WARN, "pp.port.forwarding.get.failed");
			}
		}

		return newStatusID;
	}

	public String calcProtocolAddresses() {
		long now = pi.getUtilities().getCurrentSystemTime();
		StringBuilder sReply = new StringBuilder("Last Checked ").append(
				pi.getUtilities().getFormatters().formatDate(now)).append("\n");
		// Stolen from NetworkAdminImpl.generateDiagnostics
		// This takes some time (1s-ish), so it's better to do it on demand
		try {
			NetworkAdmin networkAdmin = NetworkAdmin.getSingleton();
			Core azureus_core = CoreFactory.getSingleton();

			NetworkAdminProtocol[] protocols = networkAdmin.getOutboundProtocols(
					azureus_core);

			for (int i = 0; i < protocols.length; i++) {

				NetworkAdminProtocol protocol = protocols[i];

				try {

					InetAddress ext_addr = networkAdmin.testProtocol(protocol);

					String country = null;
					if (ext_addr != null) {

						List<LocationProvider> locationProviders = pi.getUtilities().getLocationProviders();
						for (LocationProvider locationProvider : locationProviders) {
							country = locationProvider.getCountryNameForIP(ext_addr,
									Locale.getDefault());
							if (country != null) {
								break;
							}
						}
					}

					addLiteralReply(sReply, protocol.getName() + " - " + ext_addr
							+ (country == null ? "" : " - " + country));

				} catch (NetworkAdminException e) {

					addLiteralReply(sReply,
							protocol.getName() + " - " + Debug.getNestedExceptionMessage(e));
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
			addReply(sReply, CHAR_BAD, "pp.nat.error", new String[] {
				e.toString()
			});
		}

		lastProtocolAddresses = sReply.toString();

		CheckerPPListener[] triggers = listeners.toArray(new CheckerPPListener[0]);
		for (CheckerPPListener l : triggers) {
			try {
				l.protocolAddressesStatusChanged(lastProtocolAddresses);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return lastProtocolAddresses;
	}

	private void addReply(StringBuilder sReply, char prefix, String id) {
		String s = (prefix == 0 ? "" : prefix + " ")
				+ texts.getLocalisedMessageText(id);
		addLiteralReply(sReply, s);
	}

	private void addReply(StringBuilder sReply, char prefix, String id,
			String[] params) {
		String s = (prefix == 0 ? "" : prefix + " ")
				+ texts.getLocalisedMessageText(id, params);
		addLiteralReply(sReply, s);
	}

	private void addLiteralReply(StringBuilder sReply, String s) {
		sReply.append(s).append("\n");
		PluginPP.log(s);
	}

	private int findBindingAddress(StringBuilder sReply) {
		int newStatusID = -1;

		// Find our VPN binding (interface) address.  Checking UDP is the best bet,
		// since TCP and http might be proxied
		List<PRUDPPacketHandler> handlers = PRUDPPacketHandlerFactory.getHandlers();
		if (handlers.size() == 0) {
			PRUDPReleasablePacketHandler releasableHandler = PRUDPPacketHandlerFactory.getReleasableHandler(
					0);
			handlers = PRUDPPacketHandlerFactory.getHandlers();
			releasableHandler.release();
		}
		if (handlers.size() == 0) {
			addLiteralReply(sReply, CHAR_BAD + " No UDP Handlers");

			newStatusID = STATUS_ID_BAD;
		} else {

			InetAddress bindIP = handlers.get(0).getBindIP();

			// The "Any" field is equivalent to 0.0.0.0 in dotted-quad notation, which is unbound.
			// "Loopback" is 127.0.0.1, which is bound when Vuze can't bind to
			// user specified interface (ie. kill switched)
			if (bindIP.isAnyLocalAddress() || bindIP.isLoopbackAddress()) {
				newStatusID = handleUnboundOrLoopback(bindIP, sReply);
				if (newStatusID == STATUS_ID_BAD) {
					return newStatusID;
				}
			} else {
				newStatusID = handleBound(bindIP, sReply);
			}
		}
		return newStatusID;
	}

	private boolean matchesVPNIP(InetAddress address) {
		if (address == null) {
			return false;
		}
		String regex = config.getPluginStringParameter(
				PluginPP.CONFIG_VPN_IP_MATCHING);
		return Pattern.matches(regex, address.getHostAddress());
	}

	private int handleBound(InetAddress bindIP, StringBuilder sReply) {
		int newStatusID = STATUS_ID_OK;

		String s;
		boolean isGoodExistingBind = matchesVPNIP(bindIP);
		if (isGoodExistingBind) {
			String niName = "Unknown Interface";
			try {
				NetworkInterface networkInterface = NetworkInterface.getByInetAddress(
						bindIP);
				niName = networkInterface.getName() + " ("
						+ networkInterface.getDisplayName() + ")";
			} catch (Throwable e) {
			}
			addReply(sReply, CHAR_GOOD, "pp.bound.good", new String[] {
				"" + bindIP,
				niName
			});
			vpnIP = bindIP;
		} else {
			addReply(sReply, CHAR_BAD, "pp.bound.bad", new String[] {
				"" + bindIP
			});
			newStatusID = STATUS_ID_BAD;
		}

		try {
			// Check if default routing goes through 10.*, by connecting to address
			// via socket.  Address doesn't need to be reachable, just routable.
			// This works on Windows (in some cases), but on Mac returns a wildcard 
			// address
			DatagramSocket socket = new DatagramSocket();
			socket.connect(testSocketAddress, 0);
			InetAddress localAddress = socket.getLocalAddress();
			socket.close();

			if (!localAddress.isAnyLocalAddress()) {
				NetworkInterface networkInterface = NetworkInterface.getByInetAddress(
						localAddress);

				s = texts.getLocalisedMessageText("pp.nonvuze.probable.route",
						new String[] {
							"" + localAddress,
							networkInterface.getName() + " ("
									+ networkInterface.getDisplayName() + ")"
				});
				char replyChar = ' ';

				if ((localAddress instanceof Inet4Address)
						&& matchesVPNIP(localAddress)) {

					if (localAddress.equals(bindIP)) {
						replyChar = isGoodExistingBind ? CHAR_GOOD : CHAR_WARN;
						s += " " + texts.getLocalisedMessageText("pp.same.as.vuze");
					} else {
						// Vuze is bound, default routing goes somewhere else
						// This is ok, since Vuze will not accept incoming from "somewhere else"
						// We'll warn, but not update the status id

						replyChar = CHAR_WARN;
						s += " " + texts.getLocalisedMessageText("pp.not.same");

						if (isGoodExistingBind) {
							s += " " + texts.getLocalisedMessageText(
									"default.routing.not.vpn.network.splitting");
						}
					}

					addLiteralReply(sReply, replyChar + " " + s);

					if (!isGoodExistingBind && rebindNetworkInterface) {
						rebindNetworkInterface(networkInterface, localAddress, sReply);
						// Should we redo test?
					}

				} else {
					// Vuze is bound, default routing goes to somewhere else.
					// Probably network splitting
					replyChar = isGoodExistingBind ? CHAR_WARN : CHAR_BAD;
					if (isGoodExistingBind) {
						s += " " + texts.getLocalisedMessageText(
								"default.routing.not.vpn.network.splitting");
					}
					addLiteralReply(sReply, replyChar + " " + s);
				}
			}
		} catch (Throwable t) {
			t.printStackTrace();
		}
		return newStatusID;
	}

	private int handleUnboundOrLoopback(InetAddress bindIP,
			StringBuilder sReply) {

		int newStatusID = STATUS_ID_OK;

		InetAddress newBindIP = null;
		NetworkInterface newBindNetworkInterface = null;

		String s;

		if (bindIP.isAnyLocalAddress()) {
			addReply(sReply, CHAR_WARN, "pp.vuze.unbound");
		} else {
			addReply(sReply, CHAR_BAD, "pp.vuze.loopback");
		}

		try {
			NetworkAdmin networkAdmin = NetworkAdmin.getSingleton();

			// Find a bindable address that starts with 10.
			InetAddress[] bindableAddresses = networkAdmin.getBindableAddresses();

			for (InetAddress bindableAddress : bindableAddresses) {
				if (matchesVPNIP(bindableAddress)) {
					newBindIP = bindableAddress;
					newBindNetworkInterface = NetworkInterface.getByInetAddress(
							newBindIP);

					addReply(sReply, CHAR_GOOD, "pp.found.bindable.vpn", new String[] {
						"" + newBindIP
					});

					break;
				}
			}

			// Find a Network Interface that has an address that starts with 10.
			NetworkAdminNetworkInterface[] interfaces = networkAdmin.getInterfaces();

			boolean foundNIF = false;
			for (NetworkAdminNetworkInterface networkAdminInterface : interfaces) {
				NetworkAdminNetworkInterfaceAddress[] addresses = networkAdminInterface.getAddresses();
				for (NetworkAdminNetworkInterfaceAddress a : addresses) {
					InetAddress address = a.getAddress();
					if (address instanceof Inet4Address) {
						if (matchesVPNIP(address)) {
							s = texts.getLocalisedMessageText("pp.possible.vpn",
									new String[] {
										"" + address,
										networkAdminInterface.getName() + " ("
												+ networkAdminInterface.getDisplayName() + ")"
							});

							if (newBindIP == null) {
								foundNIF = true;
								newBindIP = address;

								// Either one should work
								//newBindNetworkInterface = NetworkInterface.getByInetAddress(newBindIP);
								newBindNetworkInterface = NetworkInterface.getByName(
										networkAdminInterface.getName());

								s = CHAR_GOOD + " " + s + ". "
										+ texts.getLocalisedMessageText("pp.assuming.vpn");
							} else if (address.equals(newBindIP)) {
								s = CHAR_GOOD + " " + s + ". "
										+ texts.getLocalisedMessageText("pp.same.address");
								foundNIF = true;
							} else {
								if (newStatusID != STATUS_ID_BAD) {
									newStatusID = STATUS_ID_WARN;
								}
								s = CHAR_WARN + " " + s + ". "
										+ texts.getLocalisedMessageText("pp.not.same.address");
							}

							addLiteralReply(sReply, s);

							if (rebindNetworkInterface) {
								// stops message below from being added, we'll rebind later
								foundNIF = true;
							}

						}
					}
				}
			}

			if (!foundNIF) {
				addReply(sReply, CHAR_BAD, "pp.interface.not.found");
			}

			// Check if default routing goes through 10.*, by connecting to address
			// via socket.  Address doesn't need to be reachable, just routable.
			// This works on Windows, but on Mac returns a wildcard address
			DatagramSocket socket = new DatagramSocket();
			socket.connect(testSocketAddress, 0);
			InetAddress localAddress = socket.getLocalAddress();
			socket.close();

			if (!localAddress.isAnyLocalAddress()) {
				NetworkInterface networkInterface = NetworkInterface.getByInetAddress(
						localAddress);

				s = texts.getLocalisedMessageText("pp.nonvuze.probable.route",
						new String[] {
							"" + localAddress,
							networkInterface == null ? "null" : networkInterface.getName()
									+ " (" + networkInterface.getDisplayName() + ")"
				});

				if ((localAddress instanceof Inet4Address)
						&& matchesVPNIP(localAddress)) {

					if (newBindIP == null) {
						newBindIP = localAddress;
						newBindNetworkInterface = networkInterface;

						s = CHAR_GOOD + " " + s + " "
								+ texts.getLocalisedMessageText("pp.assuming.vpn");
					} else if (localAddress.equals(newBindIP)) {
						s = CHAR_GOOD + " " + s + " "
								+ texts.getLocalisedMessageText("pp.same.address");
					} else {
						// Vuze not bound. We already found a boundable address, but it's not this one
						/* Possibly good case:
						 * - Vuze: unbound
						 * - Found Bindable: 10.100.1.6
						 * - Default Routing: 10.255.1.1
						 * -> Split network
						 */
						if (newStatusID != STATUS_ID_BAD) {
							newStatusID = STATUS_ID_WARN;
						}
						s = CHAR_WARN + " " + s + " "
								+ texts.getLocalisedMessageText("pp.not.same.future.address")
								+ " "
								+ texts.getLocalisedMessageText(
										"default.routing.not.vpn.network.splitting")
								+ " " + texts.getLocalisedMessageText(
										"default.routing.not.vpn.network.splitting.unbound");
					}

					addLiteralReply(sReply, s);

				} else {
					s = CHAR_WARN + " " + s;
					if (!bindIP.isLoopbackAddress()) {
						s += " " + texts.getLocalisedMessageText(
								"default.routing.not.vpn.network.splitting");
					}

					if (newBindIP == null && foundNIF) {
						if (newStatusID != STATUS_ID_BAD) {
							newStatusID = STATUS_ID_WARN;
						}
						s += " " + texts.getLocalisedMessageText(
								"default.routing.not.vpn.network.splitting.unbound");
					}

					addLiteralReply(sReply, s);
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
			addReply(sReply, CHAR_BAD, "pp.nat.error", new String[] {
				e.toString()
			});
		}

		if (newBindIP == null) {
			addReply(sReply, CHAR_BAD, "pp.vpn.ip.detect.fail");
			return STATUS_ID_BAD;
		}

		rebindNetworkInterface(newBindNetworkInterface, newBindIP, sReply);
		return newStatusID;
	}

	/**
	 * @return rebind sucessful, or rebinding to already bound address
	 */
	private boolean rebindNetworkInterface(NetworkInterface networkInterface,
			InetAddress onlyToAddress, final StringBuilder sReply) {
		vpnIP = onlyToAddress;

		/**
		if (true) {
			sReply.append("Would rebind to " + networkInterface.getDisplayName()
					+ onlyToAddress + "\n");
			return false;
		}
		/**/
		String ifName = networkInterface.getName();

		String configBindIP = config.getCoreStringParameter(
				PluginConfig.CORE_PARAM_STRING_LOCAL_BIND_IP);

		int bindNetworkInterfaceIndex = -1;
		if (onlyToAddress != null) {
			Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
			for (int j = 0; inetAddresses.hasMoreElements(); j++) {
				InetAddress element = inetAddresses.nextElement();
				if (element.equals(onlyToAddress)) {
					bindNetworkInterfaceIndex = j;
					break;
				}
			}
		}

		if (configBindIP.equals(ifName)
				|| (bindNetworkInterfaceIndex >= 0 && configBindIP.equals(
						ifName + "[" + bindNetworkInterfaceIndex + "]"))) {

			addReply(sReply, CHAR_GOOD, "pp.already.bound.good", new String[] {
				ifName
			});
		} else {
			String newConfigBindIP = ifName;
			if (bindNetworkInterfaceIndex >= 0) {
				newConfigBindIP += "[" + bindNetworkInterfaceIndex + "]";
			}

			final AESemaphore sem = new AESemaphore("PP BindWait");

			NetworkAdmin.getSingleton().addPropertyChangeListener(
					new NetworkAdminPropertyChangeListener() {
						@Override
						public void propertyChanged(String property) {
							if (property.equals(NetworkAdmin.PR_DEFAULT_BIND_ADDRESS)) {
								sem.releaseForever();
								NetworkAdmin.getSingleton().removePropertyChangeListener(this);

								addReply(sReply, CHAR_GOOD, "pp.bind.complete.triggered");
							}
						}
					});

			// I think setting CORE_PARAM_STRING_LOCAL_BIND_IP is actually synchronous
			// We set up a PropertyChangeListener in case it ever becomes asynchronous
			config.setCoreStringParameter(
					PluginConfig.CORE_PARAM_STRING_LOCAL_BIND_IP, newConfigBindIP);
			config.setUnsafeBooleanParameter("Enforce Bind IP", true);
			config.setUnsafeBooleanParameter("Check Bind IP On Start", true);

			config.setUnsafeBooleanParameter("upnp.enable", false);
			config.setUnsafeBooleanParameter("natpmp.enable", false);

			addReply(sReply, CHAR_GOOD, "pp.change.binding", new String[] {
				"" + newConfigBindIP,
				networkInterface.getName() + " (" + networkInterface.getDisplayName()
						+ ")"
			});

			sem.reserve(11000);
			return sem.isReleasedForever();
		}
		return true;
	}

	private void changePort(int port, StringBuilder sReply) {

		PluginConfig pluginConfig = pi.getPluginconfig();
		int coreTCPPort = pluginConfig.getCoreIntParameter(
				PluginConfig.CORE_PARAM_INT_INCOMING_TCP_PORT);
		int coreUDPPort = pluginConfig.getCoreIntParameter(
				PluginConfig.CORE_PARAM_INT_INCOMING_UDP_PORT);
		if (coreTCPPort != port) {
			pluginConfig.setCoreIntParameter(
					PluginConfig.CORE_PARAM_INT_INCOMING_TCP_PORT, port);
			addReply(sReply, CHAR_GOOD, "pp.changed.port", new String[] {
				"TCP",
				Integer.toString(coreTCPPort),
				Integer.toString(port)
			});
		}
		if (coreUDPPort != port) {
			pluginConfig.setCoreIntParameter(
					PluginConfig.CORE_PARAM_INT_INCOMING_UDP_PORT, port);
			addReply(sReply, CHAR_GOOD, "pp.changed.port", new String[] {
				"UDP",
				Integer.toString(coreUDPPort),
				Integer.toString(port)
			});
		}
	}

	public void addListener(CheckerPPListener l) {
		listeners.add(l);
		try {
			l.portCheckStatusChanged(lastPortCheckStatus);
			l.protocolAddressesStatusChanged(lastProtocolAddresses);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void removeListener(CheckerPPListener l) {
		listeners.remove(l);
	}

	public int getCurrentStatusID() {
		return currentStatusID;
	}
}

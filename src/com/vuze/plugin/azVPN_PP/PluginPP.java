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

import com.biglybt.pif.PluginException;
import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.PluginListener;
import com.biglybt.pif.UnloadablePlugin;
import com.biglybt.pif.logging.LoggerChannel;
import com.biglybt.pif.ui.UIInstance;
import com.biglybt.pif.ui.UIManager;
import com.biglybt.pif.ui.UIManagerListener;
import com.biglybt.pif.ui.config.*;
import com.biglybt.pif.ui.model.BasicPluginConfigModel;
import com.biglybt.pif.ui.model.BasicPluginViewModel;
import com.biglybt.ui.swt.pif.UISWTInstance;

public class PluginPP
	implements UnloadablePlugin, UIManagerListener, PluginListener
{
	private static final String CONFIG_SECTION_ID = "vpn_pp";

	public static final String CONFIG_CHECK_MINUTES = "check.minutes";

	public static final String CONFIG_VPN_IP_MATCHING = "vpn.ip.regex";

	public static final String CONFIG_DO_PORT_FORWARDING = "vpn.port.forwarding";

	private static final boolean LOG_TO_STDOUT = false;

	private static final int DEFAULT_CHECK_EVERY_MINS = 2;

	private static final String DEFAULT_VPN_IP_REGEX = "10\\.[0-9]+\\.[0-9]+\\.[0-9]+";

	private PluginInterface pi;

	private static LoggerChannel logger;

	protected UIInstance uiInstance;

	public static PluginPP instance;

	public CheckerPP checkerPP;

	private BasicPluginConfigModel configModel;

	private BasicPluginViewModel model;

	private UI ui;

	private static long initializedOn;

	/* (non-Javadoc)
	 * @see com.biglybt.pif.Plugin#initialize(com.biglybt.pif.PluginInterface)
	 */
	@Override
	public void initialize(PluginInterface plugin_interface)
			throws PluginException {
		instance = this;

		initializedOn = System.currentTimeMillis();

		this.pi = plugin_interface;

		checkerPP = new CheckerPP(pi);

		plugin_interface.getUIManager().addUIListener(this);

		UIManager uiManager = pi.getUIManager();

		logger = pi.getLogger().getTimeStampedChannel(CONFIG_SECTION_ID);

		model = uiManager.createLoggingViewModel(logger, true);
		model.setConfigSectionID(CONFIG_SECTION_ID);

		setupConfigModel(uiManager);

		pi.addListener(this);
	}

	private void setupConfigModel(UIManager uiManager) {
		configModel = uiManager.createBasicPluginConfigModel(CONFIG_SECTION_ID);

		IntParameter checkMinsParameter = configModel.addIntParameter2(
				CONFIG_CHECK_MINUTES, "check.port.every.mins", DEFAULT_CHECK_EVERY_MINS,
				0, 60 * 24);
		checkMinsParameter.addListener(new ParameterListener() {
			@Override
			public void parameterChanged(Parameter param) {
				checkerPP.buildTimer();
			}
		});

		StringParameter paramRegex = configModel.addStringParameter2(
				CONFIG_VPN_IP_MATCHING, CONFIG_VPN_IP_MATCHING, DEFAULT_VPN_IP_REGEX);
		paramRegex.setMinimumRequiredUserMode(StringParameter.MODE_ADVANCED);

		configModel.addBooleanParameter2(
				CONFIG_DO_PORT_FORWARDING, CONFIG_DO_PORT_FORWARDING, true);
	}

	/* (non-Javadoc)
	 * @see com.biglybt.pif.UnloadablePlugin#unload()
	 */
	@Override
	public void unload()
			throws PluginException {

		if (pi != null) {
			UIManager uiManager = pi.getUIManager();
			if (uiManager != null) {
				uiManager.removeUIListener(this);
			}
			pi.removeListener(this);
		}

		if (ui != null) {
			ui.destroy();
			ui = null;
		}

		if (configModel != null) {
			configModel.destroy();
		}
		if (model != null) {
			model.destroy();
		}

		if (checkerPP != null) {
			checkerPP.destroy();
			checkerPP = null;
		}
	}

	/* (non-Javadoc)
	 * @see com.biglybt.pif.PluginListener#initializationComplete()
	 */
	@Override
	public void initializationComplete() {
		if (checkerPP == null) {
			return;
		}
		try {
			checkerPP.portBindingCheck();
			checkerPP.calcProtocolAddresses();
		} catch (Throwable t) {
			t.printStackTrace();
		}
		checkerPP.buildTimer();
	}

	/* (non-Javadoc)
	 * @see com.biglybt.pif.PluginListener#closedownInitiated()
	 */
	@Override
	public void closedownInitiated() {
	}

	/* (non-Javadoc)
	 * @see com.biglybt.pif.PluginListener#closedownComplete()
	 */
	@Override
	public void closedownComplete() {
	}

	/* (non-Javadoc)
	 * @see com.biglybt.pif.ui.UIManagerListener#UIDetached(com.biglybt.pif.ui.UIInstance)
	 */
	@Override
	public void UIDetached(UIInstance instance) {
		if (instance instanceof UISWTInstance) {
			if (ui != null) {
				ui.destroy();
				ui = null;
			}
			uiInstance = null;
		}
	}

	/* (non-Javadoc)
	 * @see com.biglybt.pif.ui.UIManagerListener#UIAttached(com.biglybt.pif.ui.UIInstance)
	 */
	@Override
	public void UIAttached(UIInstance instance) {
		if (instance instanceof UISWTInstance) {
			UISWTInstance swtInstance = (UISWTInstance) instance;
			ui = new UI(pi, swtInstance);
		}
		uiInstance = instance;
	}

	public static void log(String s) {
		if (s == null) {
			return;
		}
		if (s.endsWith("\n")) {
			s = s.substring(0, s.length() - 1);
		}
		if (LOG_TO_STDOUT || logger == null) {
			long offsetTime = System.currentTimeMillis() - initializedOn;
			System.out.println(offsetTime + "] LOGGER: " + s);
		}
		if (logger == null) {
			return;
		}
		logger.log(s);
	}

}

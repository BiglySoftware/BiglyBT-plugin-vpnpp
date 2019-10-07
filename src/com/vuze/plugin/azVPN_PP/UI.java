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

import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import com.biglybt.core.config.COConfigurationManager;
import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.ui.UIInstance;
import com.biglybt.pif.ui.UIManager;
import com.biglybt.pif.ui.menus.MenuItem;
import com.biglybt.pif.ui.menus.MenuItemListener;
import com.biglybt.pif.ui.menus.MenuManager;
import com.biglybt.pif.utils.LocaleUtilities;
import com.biglybt.ui.swt.pif.UISWTInstance;

import com.biglybt.ui.UIFunctionsManager;
import com.biglybt.ui.common.viewtitleinfo.ViewTitleInfo;
import com.biglybt.ui.common.viewtitleinfo.ViewTitleInfoManager;
import com.biglybt.ui.mdi.MdiCloseListener;
import com.biglybt.ui.mdi.MdiEntry;
import com.biglybt.ui.mdi.MdiEntryCreationListener;
import com.biglybt.ui.mdi.MultipleDocumentInterface;
import com.biglybt.ui.swt.skin.SWTSkinFactory;
import com.biglybt.ui.swt.skin.SWTSkinProperties;

public class UI implements MdiEntryCreationListener
{

	public static final String VIEW_ID = "PP_View";

	private PluginInterface pi;

	private MenuItem menuItemShowView;

	public UI(PluginInterface pi, UISWTInstance swtInstance) {
		this.pi = pi;

		addSkinPaths();

		MultipleDocumentInterface mdi = UIFunctionsManager.getUIFunctions().getMDI();

		mdi.registerEntry(VIEW_ID, this);

		// Requires 4700
		mdi.loadEntryByID(VIEW_ID, false, true, null);

		UIManager uiManager = pi.getUIManager();
		menuItemShowView = uiManager.getMenuManager().addMenuItem(
				MenuManager.MENU_MENUBAR, "ConfigView.section.vpn_pp");
		menuItemShowView.setDisposeWithUIDetach(UIInstance.UIT_SWT);
		menuItemShowView.addListener(new MenuItemListener() {

			@Override
			public void selected(MenuItem menu, Object target) {
				MultipleDocumentInterface mdi = UIFunctionsManager.getUIFunctions().getMDI();
				mdi.showEntryByID(UI.VIEW_ID);
			}
		});

		//swtInstance.addView(UISWTInstance.VIEW_MAIN, VIEW_ID, view.class, swtInstance);
	}
	
	public void destroy() {
		if (menuItemShowView != null) {
			menuItemShowView.remove();
			menuItemShowView = null;
		}
	}
	

	/* (non-Javadoc)
	 * @see MdiEntryCreationListener#createMDiEntry(java.lang.String)
	 */
	@Override
	public MdiEntry createMDiEntry(String id) {
		final MultipleDocumentInterface mdi = UIFunctionsManager.getUIFunctions().getMDI();
		MdiEntry entry = mdi.createEntryFromSkinRef(null, VIEW_ID, "ppview",
				"PP", null, null, true, null);
		entry.setTitleID("ConfigView.section.vpn_pp");
		
		final ViewTitleInfo viewTitleInfo = new ViewTitleInfo() {
			@Override
			public Object getTitleInfoProperty(int propertyID) {
				if (propertyID == ViewTitleInfo.TITLE_INDICATOR_TEXT) {
					int statusID = PluginPP.instance.checkerPP.getCurrentStatusID();
					
					LocaleUtilities texts = UI.this.pi.getUtilities().getLocaleUtilities();

					if (statusID == CheckerPP.STATUS_ID_OK) {
						return texts.getLocalisedMessageText("pp.indicator.ok");
					}
					if (statusID == CheckerPP.STATUS_ID_BAD) {
						return texts.getLocalisedMessageText("pp.indicator.bad");
					}
					if (statusID == CheckerPP.STATUS_ID_WARN) {
						return texts.getLocalisedMessageText("pp.indicator.warn");
					}
					return null;
				}
				if (propertyID == ViewTitleInfo.TITLE_INDICATOR_COLOR) {
					int statusID = PluginPP.instance.checkerPP.getCurrentStatusID();

					if (statusID == CheckerPP.STATUS_ID_OK) {
						return new int[] { 0, 80, 0 };
					}
					if (statusID == CheckerPP.STATUS_ID_BAD) {
						return new int[] { 128, 30, 30 };
					}
					if (statusID == CheckerPP.STATUS_ID_WARN) {
						return new int[] { 255, 140, 0 };
					}
					return null;
				}
				return null;
			}
		};
		
		entry.setViewTitleInfo(viewTitleInfo);

		final CheckerPPListener checkerListener = new CheckerPPListener() {

			@Override
			public void protocolAddressesStatusChanged(String status) {
			}

			@Override
			public void portCheckStatusChanged(String status) {
				ViewTitleInfoManager.refreshTitleInfo(viewTitleInfo);
			}

			@Override
			public void portCheckStart() {
			}
		};
		PluginPP.instance.checkerPP.addListener(checkerListener);

		entry.addListener(new MdiCloseListener() {
			@Override
			public void mdiEntryClosed(MdiEntry entry, boolean userClosed) {
				if (PluginPP.instance.checkerPP != null) {
					PluginPP.instance.checkerPP.removeListener(checkerListener);
				}
			}
		});
		return entry;
	}


	private void addSkinPaths() {
		String path = "com/vuze/plugin/azVPN_PP/skins/";

		String sFile = path + "skin3_vpn_pp";

		ClassLoader loader = PluginPP.class.getClassLoader();

		SWTSkinProperties skinProperties = SWTSkinFactory.getInstance().getSkinProperties();

		try {
			ResourceBundle subBundle = ResourceBundle.getBundle(sFile,
					Locale.getDefault(), loader);

			skinProperties.addResourceBundle(subBundle, path, loader);

		} catch (MissingResourceException mre) {

			mre.printStackTrace();
		}
	}
}

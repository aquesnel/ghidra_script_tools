package aquesnel.ghidra.utils.data;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.listing.Data;

public interface MixinDataSettings extends Settings {

	public Data getDataForSettings();
	
	// Default methods
	
	public default ProgramBasedDataTypeManager getDataTypeManager() {
		return getDataForSettings().getProgram().getDataTypeManager();
	}

	@Override
	public default boolean isChangeAllowed(SettingsDefinition settingsDefinition) {
		return getDataTypeManager().isChangeAllowed(getDataForSettings(), settingsDefinition);
	}

	@Override
	public default Long getLong(String name) {
		Long value = getDataTypeManager().getLongSettingsValue(getDataForSettings(), name);
		if (value == null) {
			value = getDefaultSettings().getLong(name);
		}
		return value;
	}

	@Override
	public default String getString(String name) {
		String value = getDataTypeManager().getStringSettingsValue(getDataForSettings(), name);
		if (value == null) {
			value = getDefaultSettings().getString(name);
		}
		return value;
	}

	@Override
	public default Object getValue(String name) {
		Object value = getDataTypeManager().getSettings(getDataForSettings(), name);
		if (value == null) {
			value = getDefaultSettings().getValue(name);
		}
		return value;
	}

	@Override
	public default void setLong(String name, long value) {
		getDataTypeManager().setLongSettingsValue(getDataForSettings(), name, value);
	}

	@Override
	public default void setString(String name, String value) {
		getDataTypeManager().setStringSettingsValue(getDataForSettings(), name, value);
	}

	@Override
	public default void setValue(String name, Object value) {
		getDataTypeManager().setSettings(getDataForSettings(), name, value);
	}

	@Override
	public default void clearSetting(String name) {
		getDataTypeManager().clearSetting(getDataForSettings(), name);
	}

	@Override
	public default void clearAllSettings() {
		getDataTypeManager().clearAllSettings(getDataForSettings());
	}

	@Override
	public default String[] getNames() {
		return getDataTypeManager().getInstanceSettingsNames(getDataForSettings());
	}

	@Override
	public default boolean isEmpty() {
		return getDataTypeManager().isEmptySetting(getDataForSettings());
	}

	@Override
	public default Settings getDefaultSettings() {
		return getDataForSettings().getDataType().getDefaultSettings();
	}

}

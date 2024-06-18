package aquesnel.ghidra.utils.data;

import java.util.Objects;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.listing.Data;

public class DataTypeSettingsAdapter implements Settings {

	private final ProgramBasedDataTypeManager mDataMgr;
	private final Data mData;
	
	public DataTypeSettingsAdapter(Data data) {
		this(data.getProgram().getDataTypeManager(), data);
	}
	
	public DataTypeSettingsAdapter(ProgramBasedDataTypeManager dataMgr, Data data) {
		mDataMgr = Objects.requireNonNull(dataMgr);
		mData = Objects.requireNonNull(data);
	}

	@Override
	public boolean isChangeAllowed(SettingsDefinition settingsDefinition) {
		return mDataMgr.isChangeAllowed(mData, settingsDefinition);
	}

	@Override
	public Long getLong(String name) {
		Long value = mDataMgr.getLongSettingsValue(mData, name);
		if (value == null) {
			value = getDefaultSettings().getLong(name);
		}
		return value;
	}

	@Override
	public String getString(String name) {
		String value = mDataMgr.getStringSettingsValue(mData, name);
		if (value == null) {
			value = getDefaultSettings().getString(name);
		}
		return value;
	}

	@Override
	public Object getValue(String name) {
		Object value = mDataMgr.getSettings(mData, name);
		if (value == null) {
			value = getDefaultSettings().getValue(name);
		}
		return value;
	}

	@Override
	public void setLong(String name, long value) {
		mDataMgr.setLongSettingsValue(mData, name, value);
	}

	@Override
	public void setString(String name, String value) {
		mDataMgr.setStringSettingsValue(mData, name, value);
	}

	@Override
	public void setValue(String name, Object value) {
		mDataMgr.setSettings(mData, name, value);
	}

	@Override
	public void clearSetting(String name) {
		mDataMgr.clearSetting(mData, name);
	}

	@Override
	public void clearAllSettings() {
		mDataMgr.clearAllSettings(mData);
	}

	@Override
	public String[] getNames() {
		return mDataMgr.getInstanceSettingsNames(mData);
	}

	@Override
	public boolean isEmpty() {
		return mDataMgr.isEmptySetting(mData);
	}

	@Override
	public Settings getDefaultSettings() {
		return mData.getDataType().getDefaultSettings();
	}

}

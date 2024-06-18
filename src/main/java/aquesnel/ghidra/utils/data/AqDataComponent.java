package aquesnel.ghidra.utils.data;

import java.util.Objects;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;

public class AqDataComponent extends AqDataStub {

	private final DataTypeComponent mComponentType;
	private final int mComponantIndex;
	private final int mOffset;

	/**
	 * Copied from {@link ghidra.program.database.code.DataDB#getComponent(int)}
	 */
	public AqDataComponent(Data parent, int index) {
		super(Objects.requireNonNull(parent), 
				getComponantDataTypeFromParent(parent, index), 
				parent.getProgram());
		
		validateIndex(parent, index);
		mComponantIndex = index;
		DataType parentDataType = parent.getBaseDataType();
		
		if (parentDataType instanceof Array array) {
			mComponentType = null;
			mOffset = index * array.getElementLength();
		}
		else if (parentDataType instanceof Composite composite) {
			mComponentType = composite.getComponent(index);
			mOffset = mComponentType.getOffset();
			
		}
//		else if (baseDataType instanceof DynamicDataType) {
//			DynamicDataType ddt = (DynamicDataType) baseDataType;
//			DataTypeComponent dtc = ddt.getComponent(index, this);
//			Address componentAddr = address.add(dtc.getOffset());
//			return new DataComponent(codeMgr, componentCache, componentAddr,
//				addressMap.getKey(componentAddr, false), this, dtc);
//		}
		else {
			throw new IllegalArgumentException("Unsupported Parent DataType. Got: " + parentDataType.toString());
		}
	}
	
	private static void validateIndex(Data parent, int index) {
		
		if (index < 0 || index >= parent.getNumComponents()) {
			throw new IndexOutOfBoundsException(
					"Allowed Range: [0, " 
					+ Integer.toString(parent.getNumComponents()) 
					+ "], got = " 
					+ Integer.toString(index));
		}
	}
	
	private static DataType getComponantDataTypeFromParent(Data parent, int index) {

		Objects.requireNonNull(parent);
		validateIndex(parent, index);
		DataType baseDataType = parent.getBaseDataType();
		
		if (baseDataType instanceof Array) {
			Array array = (Array) baseDataType;
			return array.getDataType();
		}
		if (baseDataType instanceof Composite) {
			Composite composite = (Composite) baseDataType;
			return composite.getComponent(index).getDataType();
		}
//		if (baseDataType instanceof DynamicDataType) {
//			DynamicDataType ddt = (DynamicDataType) baseDataType;
//			DataTypeComponent dtc = ddt.getComponent(index, this);
//			Address componentAddr = address.add(dtc.getOffset());
//			return new DataComponent(codeMgr, componentCache, componentAddr,
//				addressMap.getKey(componentAddr, false), this, dtc);
//		}
		throw new IllegalArgumentException("Unsupported Parent DataType. Got: " + baseDataType.toString());
	}

	@Override
	public int[] getComponentPath() {
		int level = getParent().getComponentLevel() + 1;
		int[] path = new int[level];
		int parentLevel = level - 1;
		path[parentLevel--] = mComponantIndex;

		Data parentData = getParent();
		while (parentData != null) {
			path[parentLevel--] = parentData.getComponentIndex();
			parentData = parentData.getParent();
		}
		return path;
	}

	@Override
	public String getFieldName() {
		if (mComponentType == null) { // is array?
			return "[" + getComponentIndex() + "]";
		}
		String myName = mComponentType.getFieldName();
		if (myName == null || myName.length() == 0) {
			myName = mComponentType.getDefaultFieldName();
		}
		return myName;
	}

	@Override
	public String getPathName() {
		String parentPath = getParent().getPathName();
		return getComponentName(parentPath);
	}

	@Override
	public String getComponentPathName() {
		String parentPath = getParent().getComponentPathName();
		return getComponentName(parentPath);
	}

	private String getComponentName(String parentPath) {
		StringBuffer stringBuffer = new StringBuffer();
		if (parentPath != null && parentPath.length() > 0) {
			stringBuffer.append(parentPath);
			if (mComponentType != null) { // not an array?
				stringBuffer.append('.');
			}
		}
		String myName = getFieldName();
		stringBuffer.append(myName);
		return stringBuffer.toString();
	}

	@Override
	public Data getRoot() {
		return getParent().getRoot();
	}

	@Override
	public int getRootOffset() {
		return getParent().getRootOffset() + getParentOffset();
	}

	@Override
	public int getParentOffset() {
		return mOffset;
	}

	@Override
	public int getComponentIndex() {
		return mComponantIndex;
	}

	@Override
	public Address getAddress() {
		return getParent().getAddress().add(mOffset);
	}

	@Override
	public boolean equals(Object obj) {

		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (obj.getClass() != AqDataComponent.class) {
			return false;
		}
		AqDataComponent data = (AqDataComponent) obj;
		if ((getComponentIndex() != data.getComponentIndex()) || (mOffset != data.mOffset)) {
			return false;
		}
		return super.equals(obj);
	}

	@Override
	public int getBytes(byte[] b, int offset) {
		return getParent().getBytes(b, mOffset + offset);
	}

	@Override
	public byte[] getBytes() throws MemoryAccessException {
		byte[] b = new byte[getLength()];
		if (getParent().getBytes(b, mOffset) != getLength()) {
			throw new MemoryAccessException("Couldn't get all bytes for AqDataComponent");
		}
		return b;
	}

	@Override
	public byte getByte(int n) throws MemoryAccessException {
		return getParent().getByte(mOffset + n);
	}
	
	@Override
	public boolean isBigEndian() {
		return getParent().isBigEndian();
	}

	@Override
	public String getComment(int commentType) {
		String cmt = super.getComment(commentType);
		if (cmt == null && commentType == CodeUnit.EOL_COMMENT && mComponentType != null) {
			cmt = mComponentType.getComment();
		}
		return cmt;
	}

	@Override
	public Settings getDefaultSettings() {
		if (mComponentType != null) {
			return mComponentType.getDefaultSettings();
		}
		return super.getDefaultSettings();
	}
}

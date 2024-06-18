package aquesnel.ghidra.utils.data;

import java.util.Objects;

import aquesnel.ghidra.utils.FlatDebuggerAPIUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;

public class PointerSliceData extends AqDataStub implements Data {

	private final int mStartIndexInclusive;
	private final int mEndIndexExclusive;
	private final GhidraScript mScript;
	
	public PointerSliceData(GhidraScript script, Data parent, final int startIndexInclusive, final int endIndexExclusive) {
		super(parent,
				makeArrayDataType(parent, startIndexInclusive, endIndexExclusive), 
				parent.getProgram());

		validateParentDataType(parent);
		validateArrayIndices(startIndexInclusive, endIndexExclusive);
		mStartIndexInclusive = startIndexInclusive;
		mEndIndexExclusive = endIndexExclusive;
		mScript = Objects.requireNonNull(script);
	}
	
	private static DataType makeArrayDataType(Data parent, final int startIndexInclusive, final int endIndexExclusive) {

		validateArrayIndices(startIndexInclusive, endIndexExclusive);
		return new ArrayDataType(
				getElementDataTypeFromParent(parent), 
				getNumElements(startIndexInclusive, endIndexExclusive), 
				getElementDataTypeFromParent(parent).getLength(),
				parent.getDataType().getDataTypeManager());
	}
	
	private static void validateArrayIndices(final int startIndexInclusive, final int endIndexExclusive) {
		
		// validate start and end are in order
		if (endIndexExclusive < startIndexInclusive) {
			throw new IllegalArgumentException(
					"EndIndex must be greater than StartIndex. Got: StartIndex = " 
					+ Integer.toString(startIndexInclusive)
					+ ", EndIndex = "
					+ Integer.toString(endIndexExclusive));
		}
	}
	
	private static Pointer validateParentDataType(Data parent) {
		
		Objects.requireNonNull(parent);
		if (!(parent.getBaseDataType() instanceof Pointer pointerDataType)) {
			throw new IllegalArgumentException("PointerSliceData only supports the 'Pointer' data type. Got: " + parent.getBaseDataType().toString());
		}
		return pointerDataType;
	}
	
	private static DataType getElementDataTypeFromParent(Data parent) {
		return validateParentDataType(parent).getDataType();
	}
	
	private DataType getElementDataType() {
		return ((Array) getDataType()).getDataType();
	}
	
	@Override
	public String toString() {
		return "PointerSliceData {ElementDataType = "
				+ getElementDataType()
				+ ", Address = "
				+ getAddress()
				+ ", StartIndex = "
				+ Integer.toString(mStartIndexInclusive)
				+ ", EndIndex = "
				+ Integer.toString(mEndIndexExclusive)
				+ ", value = "
				+ Objects.toString(getValue(), "<null>")
				+ "}";
	}

	@Override
	public String getFieldName() {
		return getParent().getFieldName() + "[" + Integer.toString(mStartIndexInclusive) + ":" + Integer.toString(mEndIndexExclusive) + "]";
	}

	@Override
	public Address getAddress() {
		try {
			if (DataUtils.getValue(getParent()) instanceof Address pointerAddress) {
				return pointerAddress.addNoWrap(mStartIndexInclusive * getElementDataType().getLength());
			}
			else {
				throw new IllegalStateException("Parent data is expected to contain a pointer with an address. Got: " + getParent());
			}
		} catch (AddressOverflowException e) {
			throw new IllegalStateException(e);
		}
	}
	
	@Override
	public byte[] getBytes() throws MemoryAccessException {
		return FlatDebuggerAPIUtils.readMemoryBytes(mScript, getAddress(), getLength());
	}

	@Override
	public boolean isBigEndian() {
		return getParent().isBigEndian();
	}
	
	@Override
	public int getLength() {
		return getNumComponents() * getElementDataType().getLength();
	}
	
	@Override
	public int getNumComponents() {
		return getNumElements(mStartIndexInclusive, mEndIndexExclusive);
	}
	
	private static int getNumElements(int startIndexInclusive, int endIndexExclusive) {
		return endIndexExclusive - startIndexInclusive;
	}

	@Override
	public Data getComponent(int index) {
		return new AqDataComponent(this, mStartIndexInclusive + index);
	}
}

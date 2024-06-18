package aquesnel.ghidra.utils.data;

import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.Array;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;

public class ArraySliceData  extends AqDataStub implements Data {

	private final int mStartIndexInclusive;
	private final int mEndIndexExclusive;
	
	public ArraySliceData(Data parent, final int startIndex, final int endIndex) {
		super(parent, parent.getBaseDataType(), parent.getProgram());

		if (!(parent.getBaseDataType() instanceof Array)) {
			throw new IllegalArgumentException("ArraySliceData only supports the 'Array' data type. Got: " + parent.getBaseDataType().toString());
		}
		
		mStartIndexInclusive = startIndex;
		mEndIndexExclusive = endIndex;
		
		// validate start and end are inside the parent array
		if (mStartIndexInclusive < 0) {
			throw new IllegalArgumentException("StartIndex must be greater than 0. Got: " + Integer.toString(mStartIndexInclusive));
		}
		if (mEndIndexExclusive < 0) {
			throw new IllegalArgumentException("EndIndex must be greater than 0. Got: " + Integer.toString(mEndIndexExclusive));
		}
		if (parent.getNumComponents() < mStartIndexInclusive ) {
			throw new IllegalArgumentException(
					"StartIndex must be less than or equal to the size of parent Array. Got: parent Array size = " 
					+ Integer.toString(parent.getNumComponents())
					+ ", StartIndex = "
					+ Integer.toString(mStartIndexInclusive));
		}
		if (parent.getNumComponents() < mEndIndexExclusive ) {
			throw new IllegalArgumentException(
					"EndIndex must be less than or equal to the size of parent Array. Got: parent Array size = " 
					+ Integer.toString(parent.getNumComponents())
					+ ", EndIndex = "
					+ Integer.toString(mEndIndexExclusive));
		}
		
		// validate start and end are in order
		if (mEndIndexExclusive < mStartIndexInclusive) {
			throw new IllegalArgumentException(
					"EndIndex must be greater than StartIndex. Got: StartIndex = " 
					+ Integer.toString(mStartIndexInclusive)
					+ ", EndIndex = "
					+ Integer.toString(mEndIndexExclusive));
		}
	}
	
	@Override
	public String toString() {
		return "ArraySliceData {DataType = "
				+ getDataType()
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
			return getParent().getAddress().addNoWrap(mStartIndexInclusive * getParent().getBaseDataType().getLength());
		} catch (AddressOverflowException e) {
			throw new IllegalStateException(e);
		}
	}
	
	@Override
	public byte[] getBytes() throws MemoryAccessException {
		int elementLength = getParent().getBaseDataType().getLength();
		byte[] result = new byte[getLength()];
		System.arraycopy(getParent().getBytes(), 
				mStartIndexInclusive * elementLength,
				result,
				0,
				result.length);
		return result;
	}

	@Override
	public boolean isBigEndian() {
		return getParent().isBigEndian();
	}
	
	@Override
	public int getLength() {
		return getNumComponents() * getParent().getBaseDataType().getLength();
	}
	
	@Override
	public int getNumComponents() {
		return mEndIndexExclusive - mStartIndexInclusive;
	}

	@Override
	public Data getComponent(int index) {
		return getParent().getComponent(mStartIndexInclusive + index);
	}
}
